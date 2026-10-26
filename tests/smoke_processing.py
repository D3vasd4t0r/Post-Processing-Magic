"""Full frozen-worker test with our own compiled stub, NEVER a user's KAPE/evidence."""

import argparse
import io
import json
import os
import socket
import sqlite3
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from zipfile import ZipFile

from forensic_app.modes import KAPE_TEMPLATE, CommandStep, ModeStore
from forensic_app.storage import Storage

STUB = r'''
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
class Example {
 static int Main(string[] args) {
  if(args.Length == 1 && args[0] == "--child") { Thread.Sleep(120000); return 0; }
  string dest=null, source=null, module=null;
  for(int i=0;i<args.Length;i++) {
   if(args[i]=="--mdest") dest=args[++i];
   else if(args[i]=="--msource") source=args[++i];
   else if(args[i]=="--module") module=args[++i];
  }
  Console.WriteLine("SYNTHETIC STUB ONLY: " + module);
  if(module=="Failure") return 7;
  if(!Directory.Exists(source)) return 8;
  if(module=="Child") {
   Process child = Process.Start(new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,"--child")
    {UseShellExecute=false,CreateNoWindow=true});
   File.WriteAllText("child.pid",child.Id.ToString());
  }
  Directory.CreateDirectory(dest);
  File.WriteAllText(Path.Combine(dest,"result.txt"),"Synthetic output. No forensic analysis.");
  return 0;
 }
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    folder = root/".local-data"/f"processing-smoke-{time.time_ns()}"
    folder.mkdir()
    source, executable = folder/"Example.cs", folder/"kape.exe"
    source.write_text(STUB, encoding="utf-8")
    compiler = Path(os.environ["WINDIR"])/"Microsoft.NET"/"Framework64"/"v4.0.30319"/"csc.exe"
    subprocess.run([str(compiler), "/nologo", "/target:exe", "/out:"+str(executable), str(source)], check=True,
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    (folder/'Modules').mkdir()
    (folder/'Modules'/'Synthetic.mkape').write_text('Description: Own synthetic module\n',encoding='utf-8')
    storage = Storage(folder/"state")
    storage.initialize()
    modes = ModeStore(storage)
    modes.initialize()
    storage.save_tool("synthetic", "Only our compiled stub", str(executable), create=True)
    mode_id = modes.list_modes()[0]["id"]
    draft = KAPE_TEMPLATE.model_copy(deep=True)
    draft.steps[0].tool_id = "synthetic"
    draft.steps[0].parameters = r"--msource .\Targets\C --mdest .\PostMortem --module Synthetic --gui"
    modes.save(mode_id, draft, create=False)
    with socket.socket() as socket_instance:
        socket_instance.bind(("127.0.0.1", 0))
        port = socket_instance.getsockname()[1]
    base, token = f"http://127.0.0.1:{port}", ""

    def request(path, method="GET", body=None, kind="application/json"):
        headers = {"Authorization": "Bearer "+token}
        if body is not None:
            headers["Content-Type"] = kind
        with urlopen(Request(base+path, data=body, headers=headers, method=method), timeout=5) as response:
            data = response.read()
            return json.loads(data) if response.headers.get("Content-Type", "").startswith("application/json") else data

    def wait_for(ident, expected):
        for _ in range(240):
            state = request("/api/jobs/"+ident)
            if state["status"] in expected:
                return state
            if state["status"] in ("failed", "cancelled", "interrupted"):
                raise AssertionError(state)
            time.sleep(0.1)
        raise AssertionError("Synthetic worker did not finish: "+str(state))

    payload = io.BytesIO()
    with ZipFile(payload, "w") as archive:
        archive.writestr("C/README.txt", "Own synthetic test input; no real evidence.")
    with (folder/"server.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen([str(args.exe.resolve()), "--test-no-admin", "--no-browser", "--data-dir", str(storage.root), "--port", str(port)],
                                   stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            for _ in range(200):
                try:
                    token = (storage.root/"config"/"access-token.txt").read_text().strip()
                    if request("/health") and request("/api/jobs/catalog")["worker"]:
                        break
                except (OSError, URLError, HTTPError):
                    time.sleep(0.1)
            else:
                raise AssertionError("Server/worker not ready; see "+str(folder))
            reports = []
            for module in ("Synthetic", "Failure", "Child", "Local", "Workflow"):
                if module == 'Synthetic':
                    request('/api/queue','PUT',b'{"paused":true}')
                draft.steps[0].parameters = rf"--msource .\Targets\C --mdest .\PostMortem --module {module} --gui"
                if module == "Workflow":
                    draft.steps.insert(0, CommandStep(type="powershell", name="Prepare folder", script="Start-Sleep -Milliseconds 1000; New-Item -ItemType Directory PostMortem -Force | Out-Null; Set-Content PostMortem/before.txt 'before'"))
                    draft.steps.append(CommandStep(type="powershell", name="After KAPE", working_directory="PostMortem", script="Set-Content after.txt 'after'; 1..100 | ForEach-Object { Write-Output ('Terminal line '+$_) }"))
                modes.save(mode_id, draft, create=False)
                if module == "Local":
                    local_archive = folder/"G-drive.zip"
                    with ZipFile(local_archive, "w") as archive:
                        archive.writestr("G/README.txt", "Own local G-drive test.")
                    ident = request("/api/jobs/local", "POST", json.dumps({"mode_id": mode_id,"path":str(local_archive)}).encode())["id"]
                    assert not (storage.root/"evidence"/ident).exists()
                else:
                    ident = request("/api/jobs?"+urlencode({"mode_id": mode_id, "filename": "sample.zip"}),
                                    "POST", payload.getvalue(), "application/zip")["id"]
                if module == 'Synthetic':
                    time.sleep(0.4)
                    assert request('/api/jobs/'+ident)['status'] == 'queued'
                    assert not (storage.root/'work'/ident).exists()
                    request('/api/queue','PUT',b'{"paused":false}')
                if module == 'Workflow':
                    wait_for(ident, ('running',))
                    request('/api/queue','PUT',b'{"paused":true}')
                if module == "Child":
                    pid_file = storage.root/"work"/ident/"child.pid"
                    for _ in range(200):
                        if pid_file.exists():
                            break
                        time.sleep(0.1)
                    assert pid_file.exists(), request("/api/jobs/"+ident)
                    child_pid = int(pid_file.read_text())
                    request("/api/jobs/"+ident+"/cancel", "POST")
                    state = wait_for(ident, ("cancelled",))
                    listing = subprocess.run(["tasklist", "/FI", f"PID eq {child_pid}", "/FO", "CSV", "/NH"],
                                             capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout
                    assert f'"{child_pid}"' not in listing, "Child survived cancellation"
                elif module == "Failure":
                    state = wait_for(ident, ("failed",))
                    assert state["exit_code"] == 7
                else:
                    state = wait_for(ident, ("succeeded",))
                    if module == 'Synthetic':
                        with sqlite3.connect(storage.database) as connection:
                            frozen=json.loads(connection.execute('SELECT config_json FROM jobs WHERE id=?',(ident,)).fetchone()[0])
                        captured=frozen['commands'][0]['module_manifest']
                        assert 'commands' not in request('/api/jobs/'+ident+'/report?format=json')['configuration']
                        assert captured['files'][0]['relative_path']=='Modules/Synthetic.mkape'
                        assert captured['files'][0]['sha256']
                    explorer = request("/api/jobs/"+ident+"/explorer")
                    assert explorer["local"] and isinstance(explorer["available"], bool) and explorer["reason"]
                    ticket = request("/api/jobs/"+ident+"/download-ticket", "POST")
                    with urlopen(base+ticket["url"], timeout=5) as response:
                        result = response.read()
                    with ZipFile(io.BytesIO(result)) as archive:
                        assert b"Synthetic output" in archive.read("PostMortem/result.txt")
                        assert "KAPE-Kommandozeile.log" not in archive.namelist()
                        assert "SYNTHETIC STUB ONLY" in state["log_tail"]
                        if module == "Workflow":
                            assert state["completed"] == state["total"] == 3
                            assert b"before" in archive.read("PostMortem/before.txt")
                            assert b"after" in archive.read("PostMortem/after.txt")
                            assert "Terminal line 100" in state["log_tail"]
                            assert request('/api/queue')['paused']
                            request('/api/queue','PUT',b'{"paused":false}')
                    if module == "Local":
                        assert state["source_resolution"]["effective"] == "Targets\\G"
                        assert state["input_sha256"]
                        assert not (storage.root/"evidence"/ident).exists()
                    else:
                        assert (storage.root/"evidence"/ident/"Evidence.zip").read_bytes() == payload.getvalue()
                reports.append({"id": ident, "test": module, "status": state["status"]})
            overview = request('/api/settings/storage')
            history = request('/api/jobs')
            assert sum(job['status'] == 'failed' for job in history['jobs']) == 1
            assert len(request('/api/jobs?limit=2&offset=2')['jobs']) == 2
            assert overview['volume']['free_bytes'] >= 0 and overview['scan'] is None
            measured = request('/api/settings/storage/scan', 'POST')['scan']
            assert measured['complete'] and measured['bytes'] > 0 and len(measured['areas']) == 3
            changed=folder/'Modules'/'Tampered.mkape'
            changed.write_text('Description: Before capture\n',encoding='utf-8')
            draft=KAPE_TEMPLATE.model_copy(deep=True)
            draft.steps[0].tool_id='synthetic'
            draft.steps[0].parameters=r'--msource .\Targets\C --mdest .\PostMortem --module Tampered --gui'
            modes.save(mode_id,draft,create=False)
            request('/api/queue','PUT',b'{"paused":true}')
            ident=request('/api/jobs?'+urlencode({'mode_id':mode_id,'filename':'own-tampered.zip'}),'POST',payload.getvalue(),'application/zip')['id']
            assert request('/api/jobs/'+ident)['status']=='queued'
            changed.write_text('Description: Changed after snapshot\n',encoding='utf-8')
            request('/api/queue','PUT',b'{"paused":false}')
            state=wait_for(ident,('failed',))
            assert state['error_detail']['error_code']=='error.kape_manifest_changed'
            assert 'SYNTHETIC STUB ONLY' not in state['log_tail']
            reports.append({'id':ident,'test':'Frozen module mutation blocked before process','status':state['status']})
            (folder/"report.json").write_text(json.dumps(reports, indent=2), encoding="utf-8")
            print(json.dumps({"passed": reports, "report": str(folder/"report.json")}))
        finally:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True,
                           check=False, creationflags=subprocess.CREATE_NO_WINDOW)
            process.wait(timeout=10)


if __name__ == "__main__":
    main()
