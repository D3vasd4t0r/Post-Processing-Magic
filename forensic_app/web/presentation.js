/* Presentation preferences belong to this browser, never to a workflow or job snapshot. */
const preparationViews = {forensics:'simple', malware:'simple'};
for (const area of Object.keys(preparationViews)) {
  try { if (localStorage.getItem('ppm-view-'+area)==='advanced') preparationViews[area]='advanced'; }
  catch { /* Private/restricted storage: keep an in-memory choice. */ }
}
let runTouched=false, staticTouched=false;

function isAdvancedPreparation(area=workspaceArea) { return preparationViews[area]==='advanced'; }

function updatePreparationPresentation() {
  const advanced=isAdvancedPreparation(), malware=workspaceArea==='malware';
  document.body.classList.toggle('simple-view',currentPage==='overview' && !advanced);
  byId('preparation-view').hidden=currentPage!=='overview';
  byId('onboarding').hidden=onboardingDismissed || currentPage!=='overview';
  for (const choice of ['simple','advanced']) byId('view-'+choice).setAttribute('aria-pressed',String((choice==='advanced')===advanced));
  const custom=malware ? Boolean(byId('static-case').value || byId('static-device').value || !byId('static-zip').checked) :
    Boolean(byId('run-case').value || byId('run-device').value || !byId('create-result-zip').checked || !byId('allow-high-compression').checked);
  byId('custom-options').hidden=currentPage!=='overview' || advanced || !custom;
  byId('run-status-panel').hidden=!activeJobId && !runBusy && !runTouched;
  byId('static-status-panel').hidden=!staticJobId && !staticBusy && !staticTouched;
  byId('open-settings').hidden=preparationModes.length>0 && !advanced;
  byId('static-configure').hidden=staticModules.some(m=>m.ready && m.evidence_format===byId('static-format').value) && !advanced;
  byId('ongoing-job').hidden=currentPage==='overview' || !(runBusy || staticBusy);
  setUiText(byId('page-title'),()=>t('page.'+currentPage),true);
}

async function choosePreparationView(choice) {
  if (!['simple','advanced'].includes(choice)) return;
  const source=byId(workspaceArea==='malware'?'static-source':'run-source-kind').value;
  if (choice==='simple' && source==='local') {
    setUiText(byId('presentation-message'),()=>t('view.local_guard'),true);
    byId('presentation-message').focus();
    return;
  }
  preparationViews[workspaceArea]=choice;
  try { localStorage.setItem('ppm-view-'+workspaceArea,choice); } catch { /* Session choice remains usable. */ }
  setUiText(byId('presentation-message'),()=> '');
  updatePreparationPresentation();
  byId('view-'+choice).focus();
  // Read existing persisted results only; changing the view never submits a job.
  if (choice==='advanced' && workspaceArea==='malware' && staticJobId) await refreshStaticJob();
}

function closeWorkspaceMenu(returnFocus=false) {
  document.body.classList.remove('nav-open');
  byId('menu-toggle').setAttribute('aria-expanded','false');
  if (returnFocus) byId('menu-toggle').focus();
}

byId('menu-toggle').addEventListener('click',()=>{
  const open=byId('menu-toggle').getAttribute('aria-expanded')!=='true';
  document.body.classList.toggle('nav-open',open);
  byId('menu-toggle').setAttribute('aria-expanded',String(open));
  if (open) byId('nav-'+currentPage).focus();
});
byId('nav-backdrop').addEventListener('click',()=>closeWorkspaceMenu(true));
document.addEventListener('keydown',event=>{
  if (byId('menu-toggle').getAttribute('aria-expanded')!=='true') return;
  if (event.key==='Escape') {event.preventDefault();closeWorkspaceMenu(true);}
  if (event.key==='Tab') {
    const items=[...byId('main-navigation').querySelectorAll('button:not(:disabled)')];
    const first=items[0],last=items[items.length-1];
    if (event.shiftKey && document.activeElement===first) {event.preventDefault();last.focus();}
    else if (!event.shiftKey && document.activeElement===last) {event.preventDefault();first.focus();}
  }
});
for (const choice of ['simple','advanced']) byId('view-'+choice).addEventListener('click',()=>run(()=>choosePreparationView(choice)));
byId('show-custom-options').addEventListener('click',()=>run(()=>choosePreparationView('advanced')));
byId('ongoing-job').addEventListener('click',()=>run(()=>navigate('overview')));
for (const id of ['run-case','run-device','allow-high-compression','create-result-zip','static-case','static-device','static-zip']) {
  byId(id).addEventListener('input',updatePreparationPresentation);
  byId(id).addEventListener('change',updatePreparationPresentation);
}
I18n.ready.then(updatePreparationPresentation);
