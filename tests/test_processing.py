import copy
import hashlib
import io
import json
import sqlite3
import stat
import threading
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest
from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.jobs import JobService, JobStore
from forensic_app.kape_plan import compile_plan, windows_arguments
from forensic_app.modes import KAPE_TEMPLATE, ModeStore
from forensic_app.storage import Storage
from forensic_app.windows_access import locked_input
from forensic_app.worker import process_job
from forensic_app.zip_safety import extract_checked


def archive_bytes(entries=(("C/file.txt", b"Synthetic evidence"),)):
    output = io.BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in entries:
            entry = name if isinstance(name, ZipInfo) else ZipInfo(name)
            entry.compress_type = ZIP_DEFLATED
            archive.writestr(entry, content)
    return output.getvalue()


@pytest.fixture
def setup(tmp_path, monkeypatch):
    storage = Storage(tmp_path / "state")
    storage.initialize()
    modes = ModeStore(storage)
    modes.initialize()
    executable = tmp_path / "kape.exe"
    executable.write_text("Synthetic fixture. Never execute.")
    storage.save_tool("example-kape", "KAPE example", str(executable), create=True)
    mode = modes.list_modes()[0]
    draft = copy.deepcopy(KAPE_TEMPLATE)
    draft.steps[0].tool_id = "example-kape"
    modes.save(mode["id"], draft, create=False)
    monkeypatch.setattr(JobService, "available", lambda self: True)
    with TestClient(create_app(storage, "processing-secret", test_no_admin=True), base_url="http://127.0.0.1",
                    headers={"Authorization": "Bearer processing-secret"}) as client:
        yield client, storage, mode["id"], executable


def upload(client, mode, content=None):
    return client.post("/api/jobs", params={"mode_id": mode, "filename": "synthetic.zip"},
                       content=content if content is not None else archive_bytes(), headers={"Content-Type": "application/zip"})


def plan_for(storage, ident):
    with sqlite3.connect(storage.database) as connection:
        return json.loads(connection.execute("SELECT config_json FROM jobs WHERE id=?", (ident,)).fetchone()[0])


def test_upload_queue_snapshot_success_and_download(setup):
    client, storage, mode, executable = setup
    response = upload(client, mode)
    assert response.status_code == 200, response.text
    ident = response.json()["id"]
    store = JobStore(storage)
    assert store.get(ident)["status"] == "queued"
    assert store.get(ident)["input_sha256"] == hashlib.sha256(archive_bytes()).hexdigest()
    original = (storage.root/"evidence"/ident/"Evidence.zip").read_bytes()
    plan = plan_for(storage, ident)
    assert plan["tool"]["sha256"] == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert client.get(f"/api/jobs/{ident}/download").status_code == 409

    def synthetic_runner(plan, work, check, emit):
        assert (work/"Targets"/"C"/"file.txt").read_bytes() == b"Synthetic evidence"
        output = work/"PostMortem"
        output.mkdir()
        (output/"result.txt").write_text("Synthetic analysis output")
        emit("Example tool output\n")
        return 0

    process_job(store, ident, plan, threading.Event(), runner=synthetic_runner)
    status = client.get(f"/api/jobs/{ident}").json()
    assert status["status"] == "succeeded", status
    assert status["completed"] == 1 and status["exit_code"] == 0
    downloaded = client.get(f"/api/jobs/{ident}/download")
    assert downloaded.status_code == 200
    ticket = client.post(f"/api/jobs/{ident}/download-ticket").json()
    assert client.get(ticket["url"], headers={"Authorization": ""}).content == downloaded.content
    assert client.get(ticket["url"]).status_code == 410
    assert client.get("/api/results/unknown").status_code == 410
    with ZipFile(io.BytesIO(downloaded.content)) as result:
        assert result.read("PostMortem/result.txt") == b"Synthetic analysis output"
        assert "Example tool output" in result.read("KAPE-Kommandozeile.log").decode()
        assert json.loads(result.read("Aufbereitungsprotokoll.json"))["configuration"] == plan
    assert original == (storage.root/"evidence"/ident/"Evidence.zip").read_bytes()
    assert store.get(ident)["result_sha256"] == hashlib.sha256(downloaded.content).hexdigest()
    events = store.events(ident, 0)
    assert events and all(event["id"] > 0 for event in events)
    assert store.events(ident, events[-1]["id"]) == []


@pytest.mark.parametrize("outcome", ["exit", "empty", "cancel", "restart", "badzip", "source"])
def test_failure_and_cancellation_never_publish_a_download(setup, outcome):
    client, storage, mode, _ = setup
    content = b"not a ZIP" if outcome == "badzip" else archive_bytes((("Wrong/file.txt", b"example"),)) if outcome == "source" else archive_bytes()
    ident = upload(client, mode, content).json()["id"]
    store = JobStore(storage)
    if outcome == "cancel":
        assert client.post(f"/api/jobs/{ident}/cancel").status_code == 200
    if outcome == "restart":
        store.recover()
        assert store.get(ident)["status"] == "interrupted"
        assert client.get(f"/api/jobs/{ident}/download").status_code == 409
        return

    def runner(*args):
        assert outcome in ("exit", "empty")
        return 4 if outcome == "exit" else 0
    process_job(store, ident, plan_for(storage, ident), threading.Event(), runner=runner)
    assert store.get(ident)["status"] == ("cancelled" if outcome == "cancel" else "failed")
    assert client.get(f"/api/jobs/{ident}/download").status_code == 409


def test_job_authorization_and_mode_gating(setup):
    client, storage, mode, _ = setup
    for path in ["/api/jobs/catalog", f"/api/jobs/{mode}", f"/api/jobs/{mode}/events", f"/api/jobs/{mode}/download"]:
        assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/api/jobs", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post(f"/api/jobs/{mode}/cancel", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/jobs/../../state.sqlite3").status_code == 404
    assert upload(client, "unknown").status_code == 404
    assert client.post("/api/jobs", params={"mode_id": mode, "filename": "evidence.e01"}).status_code == 422
    modes = ModeStore(storage)
    draft = copy.deepcopy(KAPE_TEMPLATE)
    modes.save(mode, draft, create=False)
    assert not client.get("/api/jobs/catalog").json()["modes"][0]["ready"]
    assert upload(client, mode).status_code == 422


def test_windows_argument_parsing_and_kape_scope(setup):
    _, storage, _, _ = setup
    assert windows_arguments('--msource ".\\Targets\\C with spaces" --gui') == ["--msource", ".\\Targets\\C with spaces", "--gui"]
    mode = ModeStore(storage).list_modes()[0]
    compile_plan(mode, storage.list_tools())
    for bad in ["--tsource C:", "--msource C:\\ --mdest PostMortem --module X", "--msource Targets\\C --mdest Other --module X",
                "--msource Targets\\C --mdest PostMortem --module X & calc.exe"]:
        altered = copy.deepcopy(mode)
        altered["steps"][0]["parameters"] = bad
        with pytest.raises(ValueError):
            compile_plan(altered, storage.list_tools())


@pytest.mark.parametrize("name", ["../escape", "C:/escape", "\\\\host\\share\\escape", "/escape", "C/file:ads", "C/CON", "C/odd.", "C/../escape"])
def test_zip_path_rejections_before_writing(tmp_path, name):
    archive = tmp_path/"bad.zip"
    archive.write_bytes(archive_bytes(((name, b"example"),)))
    with pytest.raises(ValueError):
        extract_checked(archive, tmp_path/"target", lambda: None, lambda _: None)
    assert not (tmp_path/"target").exists()


def test_zip_symlinks_collisions_and_ratio_are_rejected(tmp_path):
    link = ZipInfo("C/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    scenarios = [((link, b"../../outside"),), (("C/a", b"a"), ("c/A", b"b")),
                 (("C/a", b"file"), ("C/a/sub", b"b")), (("C/bomb", b"0"*2_000_000),)]
    for index, entries in enumerate(scenarios):
        path = tmp_path/f"bad-{index}.zip"
        path.write_bytes(archive_bytes(entries))
        with pytest.raises(ValueError):
            extract_checked(path, tmp_path/f"target-{index}", lambda: None, lambda _: None)


def test_imported_tool_in_use_remains_intact_on_delete(setup):
    client, storage, _, _ = setup
    original = client.get("/api/settings/configuration/export").json()
    preview = client.post("/api/settings/configuration/preview", json={"document": original}).json()
    assert client.post("/api/settings/configuration/apply", json={"ticket": preview["ticket"]}).status_code == 200
    tools = client.get("/api/settings/tools").json()["tools"]
    assert tools[0]["used_by"]
    before = ModeStore(storage).list_modes()
    response = client.delete("/api/settings/tools/example-kape")
    assert response.status_code == 409
    assert before[0]["name"] in response.json()["detail"]
    assert ModeStore(storage).list_modes() == before
    assert len(storage.list_tools()) == 1


def test_local_reference_has_no_upload_copy_and_resolves_g_drive(setup, tmp_path):
    client, storage, mode, _ = setup
    response = client.put('/api/settings/processing', json={"max_upload_bytes": 100, "max_extract_bytes": 2_000_000_000_000})
    assert response.status_code == 200
    assert upload(client, mode).status_code == 413  # Local source bypasses only the browser upload limit.
    path = tmp_path/"own-local.zip"
    content = archive_bytes((("G/README.txt", b"Own synthetic G-drive input"),))
    path.write_bytes(content)
    response = client.post("/api/jobs/local", json={"mode_id": mode, "path": str(path)})
    assert response.status_code == 200, response.text
    ident = response.json()["id"]
    assert not (storage.root/"evidence"/ident).exists()
    store = JobStore(storage)
    requested = plan_for(storage, ident)

    def runner(plan, work, check, emit):
        assert plan["source"] == "Targets\\G"
        assert plan["argv"][plan["argv"].index("--msource")+1] == ".\\Targets\\G"
        assert (work/"Targets"/"G"/"README.txt").is_file()
        (work/"PostMortem").mkdir()
        (work/"PostMortem"/"result.txt").write_text("Example")
        return 0
    process_job(store, ident, requested, threading.Event(), runner=runner)
    state = store.get(ident)
    assert state["status"] == "succeeded", state
    assert state["input_sha256"] == hashlib.sha256(content).hexdigest()
    assert state["source_resolution"] == {"configured": "Targets\\C", "effective": "Targets\\G"}
    assert plan_for(storage, ident) == requested  # Requested configuration stays immutable.
    assert path.read_bytes() == content


def test_local_change_between_queue_and_processing_is_rejected(setup, tmp_path):
    client, storage, mode, _ = setup
    path = tmp_path/"changing.zip"
    path.write_bytes(archive_bytes())
    ident = client.post("/api/jobs/local", json={"mode_id": mode, "path": str(path)}).json()["id"]
    path.write_bytes(b"Replaced content")
    process_job(JobStore(storage), ident, plan_for(storage, ident), threading.Event(), runner=lambda *args: pytest.fail("Must not execute"))
    state = client.get("/api/jobs/"+ident).json()
    assert state["status"] == "failed" and "verändert" in state["error"]
    assert state["error_detail"]["phase"] == "Lokale ZIP prüfen und hashen"


def test_local_read_lock_prevents_writes_and_does_not_change_input(tmp_path):
    path = tmp_path/"readonly.zip"
    path.write_bytes(b"Do not modify")
    with locked_input(path), pytest.raises(PermissionError), path.open("wb"):
        pass
    assert path.read_bytes() == b"Do not modify"


def test_g_and_h_are_ambiguous_and_never_guessed(setup):
    client, storage, mode, _ = setup
    ident = upload(client, mode, archive_bytes((("G/a.txt", b"G"), ("H/a.txt", b"H")))).json()["id"]
    store = JobStore(storage)
    process_job(store, ident, plan_for(storage, ident), threading.Event(), runner=lambda *args: pytest.fail("Must not guess"))
    assert store.get(ident)["status"] == "failed"
    assert "G" in store.get(ident)["error"] and "H" in store.get(ident)["error"]
    assert "Quellordner" in store.get(ident)["error"]


def test_admin_message_with_success_exit_code_is_still_failure(setup):
    client, storage, mode, _ = setup
    ident = upload(client, mode).json()["id"]
    def runner(plan, work, check, emit):
        emit("Administrator privileges not found! Exiting!!\n")
        return 0
    store = JobStore(storage)
    process_job(store, ident, plan_for(storage, ident), threading.Event(), runner=runner)
    state = store.get(ident)
    assert state["status"] == "failed" and state["exit_code"] == 0
    assert state["error_detail"]["type"] == "PermissionError"
    assert "UAC" in state["error_detail"]["recommendation"]
    assert client.get(f"/api/jobs/{ident}/diagnostics").status_code == 200
    assert "Administrator" in client.get(f"/api/jobs/{ident}/log").text
    assert client.get("/api/jobs").json()["jobs"][0]["id"] == ident
    assert client.get(f"/api/jobs/{ident}/diagnostics", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_high_compression_requires_explicit_permission(tmp_path):
    path = tmp_path/"own-compressed.zip"
    path.write_bytes(archive_bytes((("C/zeros.dat", b"0"*2_000_000),)))
    with pytest.raises(ValueError, match="zeros.dat"):
        extract_checked(path, tmp_path/"blocked", lambda: None, lambda _: None)
    messages = []
    extract_checked(path, tmp_path/"allowed", lambda: None, messages.append, allow_high_compression=True)
    assert (tmp_path/"allowed"/"C"/"zeros.dat").stat().st_size == 2_000_000
    assert any("Explizit erlaubt" in message for message in messages)


def test_local_routes_validate_and_reject_remote_paths(setup):
    client, _, mode, _ = setup
    for path in ["relative.zip", r"\\server\share\evidence.zip", r"C:\missing\evidence.zip"]:
        assert client.post("/api/jobs/local", json={"mode_id": mode, "path": path}).status_code == 422
    assert client.post("/api/jobs/local", json={"mode_id": mode, "path": "anything.zip"},
                       headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_launcher_requests_uac_before_starting_server(tmp_path, monkeypatch):
    from forensic_app import launcher
    calls = []
    monkeypatch.setattr(launcher, "is_admin", lambda: False)
    monkeypatch.setattr(launcher, "elevate", lambda arguments: calls.append(arguments))
    target = tmp_path/"not-created"
    arguments = ["--no-browser", "--data-dir", str(target)]
    assert launcher.main(arguments) == 0
    assert calls == [arguments] and not target.exists()
    def refuse(arguments):
        raise PermissionError("UAC refused")
    monkeypatch.setattr(launcher, "elevate", refuse)
    assert launcher.main(arguments) == 1
    assert not target.exists()


@pytest.mark.parametrize('source',['upload','local'])
def test_case_device_snapshot_search_report_and_legacy(setup,tmp_path,source):
    from forensic_app.artifacts import prepare_report, render_report
    client,storage,mode,_ = setup
    metadata = {'case_number':'CASE-Ä<script>','device_name':'DEVICE-42&test'}
    if source=='local':
        path=tmp_path/'own.zip'
        path.write_bytes(archive_bytes())
        response=client.post('/api/jobs/local',json={'mode_id':mode,'path':str(path),**metadata})
    else:
        response=client.post('/api/jobs',params={'mode_id':mode,'filename':'own.zip',**metadata},content=archive_bytes(),headers={'Content-Type':'application/zip'})
    assert response.status_code==200,response.text
    ident=response.json()['id']
    plan=plan_for(storage,ident)
    assert {k:plan[k] for k in metadata}==metadata
    store=JobStore(storage)
    assert store.get(ident)['case_number']==metadata['case_number']
    for text in metadata.values():
        assert store.search(q=text)['jobs'][0]['id']==ident
    (storage.root/"work"/ident/"PostMortem").mkdir(parents=True)
    (storage.root/"work"/ident/"PostMortem"/"own.txt").write_text("synthetic")
    report=prepare_report(store,ident,plan,[])
    assert report['device_name']==metadata['device_name']
    html=render_report(report)
    assert 'CASE-Ä&lt;script&gt;' in html and '<script>' not in html
    assert 'DEVICE-42&amp;test' in html
    for key in metadata:plan.pop(key)
    with sqlite3.connect(storage.database) as c:
        c.execute('UPDATE jobs SET config_json=? WHERE id=?',(json.dumps(plan),ident))
    assert JobStore(storage).get(ident)['case_number']==''
    assert store.search(q='CASE-Ä')['total']==0
    assert 'Nicht angegeben' in render_report(prepare_report(store,ident,plan,[]))
    assert client.post('/api/jobs',params={'mode_id':mode,'filename':'own.zip','case_number':'x'*121},content=archive_bytes(),headers={'Content-Type':'application/zip'}).status_code==422
    assert client.post('/api/jobs/local',json={'mode_id':mode,'path':'own.zip','device_name':'x'*121}).status_code==422


@pytest.mark.parametrize('drive',['C','G'])
@pytest.mark.parametrize('source',['upload','local'])
def test_inventory_snapshot_before_commands_and_csv_api(setup,tmp_path,drive,source):
    client,storage,mode,_=setup
    content=archive_bytes(((drive+'/Windows/test&.evtx',b'EVTX'),(drive+'/$MFT',b'MFT'),(drive+'/Windows/Prefetch/a.pf',b'PF'),(drive+'/Windows/System32/config/SYSTEM',b'HIVE'),(drive+'/own.txt',b'own')))
    if source=='local':
        path=tmp_path/'own.zip';path.write_bytes(content)
        response=client.post('/api/jobs/local',json={'mode_id':mode,'path':str(path)})
    else:
        response=upload(client,mode,content)
    assert response.status_code==200,response.text
    ident=response.json()['id'];store=JobStore(storage)
    def runner(plan,work,check,emit):
        # Deliberately alter the extracted tree after inventory capture.
        (work/'Targets'/drive/'late.evtx').write_text('late tool output')
        output=work/'PostMortem';output.mkdir()
        (output/'own.csv').write_text('name,value\n<script>,=1+1\nOwn,42\n',encoding='utf-8')
        return 0
    process_job(store,ident,store.plan(ident),threading.Event(),runner=runner)
    state=store.get(ident)
    assert state['status']=='succeeded',state.get('error')
    inventory=state['input_inventory']
    assert inventory['source']=='extracted_zip_tree' and inventory['complete']
    assert inventory['files']==5 and inventory['bytes']==16
    assert all(inventory['groups'][key]['files']==1 for key in ['evtx','mft','prefetch','registry','other'])
    report=client.get('/api/jobs/'+ident+'/report?format=json').json()
    assert report['input_inventory']==inventory
    assert 'test&amp;.evtx' in client.get('/api/jobs/'+ident+'/report').text
    endpoint='/api/jobs/'+ident+'/csv'
    assert client.get(endpoint).json()['files']==['own.csv']
    preview=client.get(endpoint,params={'path':'own.csv'}).json()
    assert preview['columns']==['name','value']
    assert preview['rows'][0]['values']==['<script>','=1+1']
    found=client.get(endpoint,params={'path':'own.csv','search':'own'}).json()
    assert len(found['rows'])==1 and found['rows'][0]['values'][1]=='42'
    assert client.get(endpoint,headers={'Authorization':''}).status_code==401
    for path in ['../own.csv','C:/own.csv','own.csv:stream','/own.csv','a/./own.csv']:
        assert client.get(endpoint,params={'path':path}).status_code==422
    assert client.get(endpoint,params={'path':'missing.csv'}).status_code==404
    assert client.get(endpoint,params={'path':'own.csv','search':'x'*129}).status_code==422
    with sqlite3.connect(storage.database) as c:c.execute('UPDATE cleanup_state SET active=1 WHERE id=1')
    assert client.get(endpoint).status_code==409
    with sqlite3.connect(storage.database) as c:
        c.execute('UPDATE cleanup_state SET active=0 WHERE id=1')
        c.execute('UPDATE jobs SET input_inventory_json=NULL WHERE id=?',(ident,))
    assert store.get(ident)['input_inventory'] is None
    assert inventory['files']==5
    store.update(ident,status='running')
    assert client.get(endpoint).status_code==409
