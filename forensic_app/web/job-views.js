/* Job views display processing metadata and logs only; no result file is parsed here. */
let jvLogOffset=0, jvResultOffset=0;
let jvLogListVersion=0, jvLogVersion=0, jvResultListVersion=0, jvResultVersion=0;
let jvLogTimer=null, jvResultTimer=null, jvLogId=null, jvResultId=null;
let jvResultState=null, jvSourceState=null, jvLogFollowing=true;
function jvSetLogFollow(value){jvLogFollowing=value;byId('log-follow').setAttribute('aria-pressed',String(value));}
const jvPageSize=50;
const jvLive=state=>['uploading','queued','running'].includes(state.status)||['queued','running'].includes(state.archive_status);
const jvPath=id=>'/api/jobs/'+encodeURIComponent(id);
function jvText(id,value){setUiText(byId(id),()=>String(value??''));}
function jvLabel(id,key,params={}){setUiText(byId(id),()=>t(key,params),true);}
function jvStatus(state){return t('jobview.status.'+state.status)+(state.phase?' · '+state.phase:'');}
function jvCaption(state){return [state.case_number||t('jobview.no_case'),state.device_name||t('jobview.no_device'),'ZIP',state.created_at,state.mode_name||'',String(state.id).slice(0,8)].filter(Boolean).join(' · ');}
function clearJobViewTimers(){
  clearTimeout(jvLogTimer);clearTimeout(jvResultTimer);jvLogTimer=jvResultTimer=null;
  jvLogListVersion++;jvLogVersion++;jvResultListVersion++;jvResultVersion++;
}
function jvPagination(prefix,offset,data){
  const total=Number(data.total)||0;
  byId(prefix+'-prev').disabled=offset===0;
  byId(prefix+'-next').disabled=offset+jvPageSize>=total;
  const target=prefix==='logs'?'logs-page-note':'results-note';
  jvLabel(target,total?'jobview.page':'jobview.empty',{from:offset+1,to:Math.min(offset+jvPageSize,total),total});
}
function jvClearLog(){
  jvText('log-job-output','');jvText('log-job-status','');jvText('log-job-error','');
  byId('log-job-error').hidden=true;jvText('log-work-directory','');
}
async function loadJobLogs(preferredId){
  clearTimeout(jvLogTimer);jvLogTimer=null;
  const generation=++jvLogListVersion, previous=preferredId||byId('log-job').value||activeJobId;
  jvLogVersion++;byId('log-job').disabled=true;
  const data=await api('/api/jobs?'+new URLSearchParams({limit:String(jvPageSize),offset:String(jvLogOffset)}));
  if(generation!==jvLogListVersion||currentPage!=='logs'||!token)return;
  if(jvLogOffset>0&&jvLogOffset>=data.total){jvLogOffset=Math.max(0,Math.floor(Math.max(0,data.total-1)/jvPageSize)*jvPageSize);return loadJobLogs(preferredId);}
  const select=byId('log-job');select.replaceChildren();
  for(const item of data.jobs){const option=document.createElement('option');option.value=item.id;setUiText(option,()=>jvCaption(item),true);select.append(option);}
  select.disabled=!data.jobs.length;
  if(data.jobs.some(item=>item.id===previous))select.value=previous;
  jvPagination('logs',jvLogOffset,data);
  if(!data.jobs.length){jvLogId=null;jvClearLog();jvLabel('log-job-status','jobview.empty');return;}
  await loadSelectedLog();
}
async function loadSelectedLog(){
  clearTimeout(jvLogTimer);jvLogTimer=null;
  const id=byId('log-job').value,generation=++jvLogVersion;
  if(id!==jvLogId){jvClearLog();jvLogId=id;}
  if(!id||currentPage!=='logs'||!token)return;
  let state;
  try{state=await api(jvPath(id));}
  catch(error){if(generation!==jvLogVersion||currentPage!=='logs'||id!==byId('log-job').value)return;throw error;}
  if(generation!==jvLogVersion||currentPage!=='logs'||id!==byId('log-job').value||!token)return;
  setUiText(byId('log-job-status'),()=>jvStatus(state),true);
  const detail=state.error_detail;
  jvText('log-job-error',detail?JSON.stringify(detail,null,2):(state.error||state.storage_error||state.archive_error||''));
  byId('log-job-error').hidden=!byId('log-job-error').textContent;
  jvText('log-work-directory',state.work_directory||'');
  const terminal=byId('log-job-output'), previousTop=terminal.scrollTop, follow=jvLogFollowing;
  jvText('log-job-output',[state.command||'',state.log_tail||''].filter(Boolean).join('\n\n'));
  terminal.scrollTop=follow?terminal.scrollHeight:previousTop;
  if(jvLive(state))jvLogTimer=setTimeout(()=>run(loadSelectedLog),1500);
}
function jvClearResult(){
  jvResultState=null;jvSourceState=null;
  for(const id of ['result-title','result-state','result-source-note','result-source-path'])jvText(id,'');
  for(const id of ['result-download','result-report','result-source-download','result-archive'])byId(id).disabled=true;
  byId('result-source-download').hidden=true;byId('result-source-path').hidden=true;
}
async function loadResultJobs(){
  clearTimeout(jvResultTimer);jvResultTimer=null;
  const generation=++jvResultListVersion;
  jvResultVersion++;jvResultId=null;jvClearResult();byId('result-detail').hidden=true;byId('results-list').replaceChildren();
  const data=await api('/api/jobs?'+new URLSearchParams({limit:String(jvPageSize),offset:String(jvResultOffset)}));
  if(generation!==jvResultListVersion||currentPage!=='results'||!token)return;
  if(jvResultOffset>0&&jvResultOffset>=data.total){jvResultOffset=Math.max(0,Math.floor(Math.max(0,data.total-1)/jvPageSize)*jvPageSize);return loadResultJobs();}
  jvPagination('results',jvResultOffset,data);
  for(const item of data.jobs){
    const card=document.createElement('article');card.className='panel job-card';card.dataset.job=item.id;
    const heading=document.createElement('h3');setUiText(heading,()=>jvCaption(item),true);
    const state=document.createElement('p');setUiText(state,()=>jvStatus(item),true);
    const name=document.createElement('p');setUiText(name,()=>item.filename||'');
    const button=document.createElement('button');button.type='button';setUiText(button,()=>t('jobview.open'),true);
    button.addEventListener('click',()=>run(async()=>{await loadSelectedResult(item.id);if(currentPage==='results'&&jvResultId===item.id){byId('result-detail').scrollIntoView?.({block:'start'});byId('result-title').tabIndex=-1;byId('result-title').focus?.({preventScroll:true});}},button));
    card.append(heading,name,state,button);byId('results-list').append(card);
  }
}
async function loadSelectedResult(id){
  clearTimeout(jvResultTimer);jvResultTimer=null;
  const ident=id||jvResultId,generation=++jvResultVersion;
  if(!ident||currentPage!=='results'||!token)return;
  if(ident!==jvResultId){jvResultId=ident;jvClearResult();}
  byId('result-detail').hidden=false;
  const responses=await Promise.allSettled([api(jvPath(ident)),api(jvPath(ident)+'/source')]);
  if(generation!==jvResultVersion||currentPage!=='results'||ident!==jvResultId||!token)return;
  if(responses[0].status==='rejected')throw responses[0].reason;
  const state=responses[0].value;
  jvResultState=state;jvSourceState=responses[1].status==='fulfilled'?responses[1].value:null;
  setUiText(byId('result-title'),()=>jvCaption(state),true);
  setUiText(byId('result-state'),()=>[jvStatus(state),state.storage_error,state.archive_error,state.error].filter(Boolean).join(' · '),true);
  byId('result-download').disabled=!state.result_available;
  byId('result-report').disabled=!state.report_available;
  byId('result-archive').hidden=!!state.result_available;
  byId('result-archive').disabled=!state.output_available||!!state.storage_error||['queued','running'].includes(state.archive_status);
  const source=jvSourceState;
  if(source){
    const key=source.kind==='local'?(source.available?'jobview.local_available':'jobview.local_missing'):(source.available?'jobview.upload_available':'jobview.upload_missing');
    setUiText(byId('result-source-note'),()=>t(key)+(source.filename?' · '+source.filename:'')+(source.size!=null?' · '+source.size+' B':'')+(source.reason?' · '+source.reason:''),true);
    byId('result-source-path').hidden=source.kind!=='local';jvText('result-source-path',source.kind==='local'?source.path:'');
    byId('result-source-download').hidden=source.kind!=='upload';
    byId('result-source-download').disabled=source.kind!=='upload'||!source.available;
  }else{jvLabel('result-source-note','jobview.source_error');byId('result-source-download').hidden=true;byId('result-source-path').hidden=true;jvText('result-source-path','');}
  for(const card of byId('results-list').children)card.classList.toggle('selected',card.dataset.job===ident);
  if(jvLive(state))jvResultTimer=setTimeout(()=>run(()=>loadSelectedResult(ident)),1500);
}
async function jvTicketDownload(source){
  const id=jvResultId,generation=jvResultVersion;if(!id)return;
  if(source&&(!jvSourceState||jvSourceState.kind!=='upload'||!jvSourceState.available))return;
  const ticket=await api(jvPath(id)+(source?'/source/download-ticket':'/download-ticket'),'POST');
  if(generation!==jvResultVersion||id!==jvResultId||currentPage!=='results'||!token)return;
  const prefix=source?'/api/sources/':'/api/results/';
  if(typeof ticket.url!=='string'||!ticket.url.startsWith(prefix))throw new Error(t('jobview.invalid_download'));
  const link=document.createElement('a');link.href=ticket.url;document.body.append(link);link.click();link.remove();
}
byId('log-job').addEventListener('change',()=>run(loadSelectedLog));
byId('logs-reload').addEventListener('click',()=>run(()=>loadJobLogs()));
for(const [id,step] of [['logs-prev',-jvPageSize],['logs-next',jvPageSize]])byId(id).addEventListener('click',()=>run(()=>{jvLogOffset=Math.max(0,jvLogOffset+step);return loadJobLogs();}));
byId('log-job-output').addEventListener('scroll',()=>{const output=byId('log-job-output');if(output.scrollHeight-output.scrollTop-output.clientHeight>24)jvSetLogFollow(false);});
jvSetLogFollow(true);
byId('log-follow').addEventListener('click',()=>{jvSetLogFollow(true);const output=byId('log-job-output');output.scrollTop=output.scrollHeight;});
byId('results-reload').addEventListener('click',()=>run(loadResultJobs));
for(const [id,step] of [['results-prev',-jvPageSize],['results-next',jvPageSize]])byId(id).addEventListener('click',()=>run(()=>{jvResultOffset=Math.max(0,jvResultOffset+step);return loadResultJobs();}));
byId('result-download').addEventListener('click',()=>run(()=>jvTicketDownload(false),byId('result-download')));
byId('result-source-download').addEventListener('click',()=>run(()=>jvTicketDownload(true),byId('result-source-download')));
byId('result-report').addEventListener('click',()=>run(async()=>{const id=jvResultId;if(id&&jvResultState?.report_available)await downloadLogFile(jvPath(id)+'/report?format=html','Abschlussbericht-'+id+'.html');},byId('result-report')));
byId('result-archive').addEventListener('click',()=>run(async()=>{const id=jvResultId;if(!id||!jvResultState?.output_available)return;await api(jvPath(id)+'/archive','POST');if(id===jvResultId&&currentPage==='results')await loadSelectedResult(id);},byId('result-archive')));
