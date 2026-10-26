"""Single ZIP workspace navigation preserves active jobs and user inputs."""
from test_web_i18n import NODE_HARNESS, WEB, Inventory, run_web_harness


def test_navigation_preserves_inputs_and_active_job(tmp_path):
    checks = r"""
 get('run-case').value='CASE <raw>';get('run-device').value='Device';
 get('local-zip-path').value='C:\\Synthetic\\own.zip';get('run-source-kind').value='local';
 await evaluate("activeJobId='own-job';runBusy=true;currentPage='settings';updateWorkspaceStatus();");
 assert.equal(get('ongoing-job').hidden,false);assert.equal(get('run-status-panel').hidden,false);
 assert.equal(get('run-case').value,'CASE <raw>');assert.equal(get('local-zip-path').value,'C:\\Synthetic\\own.zip');
 await evaluate("currentPage='overview';updateWorkspaceStatus();");assert.equal(get('ongoing-job').hidden,true);
 assert.equal(await evaluate('return activeJobId;'),'own-job');assert.equal(await evaluate('return runBusy;'),true);
 await evaluate("await I18n.setLocale('en');updateWorkspaceStatus();");assert.equal(get('page-title').textContent,'Processing');
 """
    marker = " console.log('ZIP workspace, persistence, drafts and raw data verified');"
    run_web_harness(tmp_path, NODE_HARNESS.replace(marker, checks + marker))


def test_main_actions_and_four_settings_categories():
    parser = Inventory()
    parser.feed((WEB / 'index.html').read_text(encoding='utf-8'))
    nodes = {n['attrs']['id']: n for n in parser.nodes if 'id' in n['attrs']}
    for page in ('overview', 'settings', 'logs', 'results', 'feedback'):
        assert 'nav-' + page in nodes
    for category in ('tools', 'modes', 'processing', 'transfer'):
        assert 'settings-' + category in nodes
    for name in ('run-case', 'run-device', 'run-start', 'cancel-run', 'run-report',
                 'download-evidences', 'log-job', 'log-job-output'):
        assert name in nodes
    assert 'view-simple' not in nodes and 'view-advanced' not in nodes
    assert 'run-terminal' not in nodes
