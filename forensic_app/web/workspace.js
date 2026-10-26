/* Navigation changes presentation only; uploads and the persistent worker keep running. */
let runTouched=false;
function updateWorkspaceStatus(){
  byId('run-status-panel').hidden=!activeJobId&&!runBusy&&!runTouched;
  byId('ongoing-job').hidden=currentPage==='overview'||!runBusy;
  setUiText(byId('page-title'),()=>t('page.'+currentPage),true);
}
function closeWorkspaceMenu(returnFocus=false){
  document.body.classList.remove('nav-open');
  byId('menu-toggle').setAttribute('aria-expanded','false');
  if(returnFocus)byId('menu-toggle').focus();
}
byId('menu-toggle').addEventListener('click',()=>{
  const open=byId('menu-toggle').getAttribute('aria-expanded')!=='true';
  document.body.classList.toggle('nav-open',open);byId('menu-toggle').setAttribute('aria-expanded',String(open));
  if(open)byId('nav-'+currentPage).focus();
});
byId('nav-backdrop').addEventListener('click',()=>closeWorkspaceMenu(true));
document.addEventListener('keydown',event=>{
  if(byId('menu-toggle').getAttribute('aria-expanded')!=='true')return;
  if(event.key==='Escape'){event.preventDefault();closeWorkspaceMenu(true);}
  if(event.key==='Tab'){
    const buttons=[...byId('main-navigation').querySelectorAll('button:not(:disabled)')],first=buttons[0],last=buttons[buttons.length-1];
    if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
    else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
  }
});
byId('ongoing-job').addEventListener('click',()=>run(()=>navigate('overview')));
I18n.ready.then(updateWorkspaceStatus);
