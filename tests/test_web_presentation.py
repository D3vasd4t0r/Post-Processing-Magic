"""Execute actual UI logic: view changes must never mutate effective job inputs."""
import re

import pytest
from test_web_i18n import NODE_HARNESS, WEB, Inventory, catalogs, run_web_harness


@pytest.mark.parametrize('checks', [
    r"""
    assert.equal(await evaluate("return preparationViews.forensics;"),'simple');
    assert.equal(await evaluate("return preparationViews.malware;"),'simple');
    await evaluate("workspaceArea='forensics';await choosePreparationView('advanced');");
    assert.equal(local.get('ppm-view-forensics'),'advanced');
    assert.equal(local.get('ppm-view-malware'),undefined);
    await evaluate("workspaceArea='malware';updatePreparationPresentation();");
    assert.equal(get('view-simple').attrs['aria-pressed'],'true');
    await evaluate("workspaceArea='forensics';updatePreparationPresentation();");
    assert.equal(get('view-advanced').attrs['aria-pressed'],'true');
    """,
    r"""
    for (const area of ['forensics','malware']) {
      const prefix=area==='malware'?'static':'run', source=area==='malware'?'static-source':'run-source-kind';
      get(prefix+'-case').value='CASE <raw>';get(prefix+'-device').value='DEVICE';
      get(prefix==='static'?'static-zip':'create-result-zip').checked=false;
      get(prefix+'-file').files=[{name:'synthetic.pdf',size:123}];
      await evaluate(`workspaceArea='${area}';currentPage='overview';await choosePreparationView('advanced');await choosePreparationView('simple');`);
      assert.equal(get('custom-options').hidden,false);
      assert.equal(get(prefix+'-case').value,'CASE <raw>');
      assert.equal(get(prefix+'-device').value,'DEVICE');
      assert.equal(get(prefix==='static'?'static-zip':'create-result-zip').checked,false);
      assert.equal(get(prefix+'-file').files[0].size,123);
      await evaluate(`await choosePreparationView('advanced');`);
      get(source).value='local';get(area==='malware'?'static-path':'local-zip-path').value='C:\\Synthetic\\own.zip';
      await evaluate("await choosePreparationView('simple');");
      assert.equal(get('view-advanced').attrs['aria-pressed'],'true');
      assert.equal(get(source).value,'local');assert.match(get('presentation-message').textContent,/Lokale Datei/);
      assert.equal(get(area==='malware'?'static-path':'local-zip-path').value,'C:\\Synthetic\\own.zip');
      get(source).value='upload';await evaluate("await choosePreparationView('simple');");
      assert.equal(get('presentation-message').textContent,'');
    }
    assert.equal(requests.filter(([url,method])=>method!=='GET'&&url!=='/api/settings/interface').length,0);
    """,
    r"""
    await evaluate("workspaceArea='malware';currentPage='overview';staticJobId='synthetic-job';globalThis.renders=0;globalThis.summaries=0;globalThis.renderEvidenceDetails=()=>{renders++;};api=async path=>{if(path.endsWith('/summary')){summaries++;return {finding_summaries:[]};}if(path.endsWith('/explorer'))return {available:false};return {workspace:'malware',status:'succeeded',archive_status:'none',phase:'done',filename:'raw',mode_name:'own',total:3,completed:3,report_available:true,result_available:false,output_available:true,updated_at:'one'};};await choosePreparationView('simple');await refreshStaticJob();");
    assert.equal(context.summaries,0);assert.equal(context.renders,0);
    assert.equal(get('static-status-panel').hidden,false);assert.equal(get('static-report').disabled,false);
    assert.equal(get('static-download').disabled,true);assert.equal(get('static-archive').disabled,false);
    assert.match(get('static-archive-note').textContent,/Kein Ergebnis-ZIP/);
    await evaluate("await choosePreparationView('advanced');");
    assert.equal(context.summaries,1);assert.equal(context.renders,1);
    await evaluate("await choosePreparationView('simple');await choosePreparationView('advanced');");
    assert.equal(context.summaries,1);assert.equal(context.renders,1);
    // A summary in flight must not suppress independent download/archive state updates.
    await evaluate("staticSummaryKey='';byId('static-archive').disabled=true;const previous=api;api=path=>path.endsWith('/summary')?new Promise(resolve=>{globalThis.releaseSummary=resolve;}):previous(path);globalThis.refreshPending=refreshStaticJob();");
    await evaluate("await choosePreparationView('simple');releaseSummary({finding_summaries:[]});await refreshPending;");
    assert.equal(context.renders,1);assert.equal(get('static-archive').disabled,false);
    """,
    r"""
    await evaluate("currentPage='logs';workspaceArea='forensics';activeJobId='unchanged';runBusy=true;updatePreparationPresentation();");
    assert.equal(get('ongoing-job').hidden,false);assert.equal(get('run-status-panel').hidden,false);
    await evaluate("await choosePreparationView('advanced');await choosePreparationView('simple');");
    assert.equal(await evaluate('return activeJobId;'),'unchanged');
    assert.equal(await evaluate('return runBusy;'),true);
    await evaluate("currentPage='overview';updatePreparationPresentation();");
    assert.equal(get('ongoing-job').hidden,true);
    await evaluate("await I18n.setLocale('en');updatePreparationPresentation();");
    assert.equal(get('page-title').textContent,'Processing');assert.equal(get('view-advanced').textContent,'Advanced');
    """,
])
def test_presentation_preserves_state_and_controls_summary_fetch(tmp_path, checks):
    harness = NODE_HARNESS.replace(
        " console.log('both areas, persistence, drafts and raw data verified');",
        checks + "\n console.log('both areas, persistence, drafts and raw data verified');")
    run_web_harness(tmp_path, harness)


def test_new_labels_and_feedback_page_have_explicit_localization():
    html=(WEB/'index.html').read_text(encoding='utf-8')
    script=(WEB/'presentation.js').read_text(encoding='utf-8')
    values=catalogs()['de']
    for key in re.findall(r"\bt\(['\"]([^'\"]+)['\"]\)",script):
        assert key in values,key
    parser=Inventory();parser.feed(html)
    nodes={node['attrs']['id']:node for node in parser.nodes if 'id' in node['attrs']}
    assert nodes['feedback']['tag']=='section'
    assert 'feedback-dialog' not in nodes and 'open-feedback' not in nodes
    assert nodes['main-navigation']['tag']=='nav'
    for name in ['overview','settings','logs','results','feedback']:
        assert nodes['nav-'+name]['attrs']['data-i18n'] in values
    assert 'data-advanced' not in nodes['run-error-panel']['attrs']
    for name in ['run-inventory','static-findings','run-terminal','static-explorer']:
        assert 'data-advanced' in nodes[name]['attrs']
