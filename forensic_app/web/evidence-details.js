/* Captured metadata only. Values use textContent: no links, network lookups or sample actions. */
function renderEvidenceDetails(report, parent, ident) {
  const label = key => t('extended.' + key);
  const appendText = (parentNode,tag,value) => {const node=document.createElement(tag);node.textContent=value ?? '';parentNode.append(node);return node;};
  const card = title => {const node=document.createElement('section');appendText(node,'h3',title);parent.append(node);return node;};
  const metadataStatus = value => ({completed:t('web.s511'),limited:t('web.s512'),unsupported:t('web.s513'),error:t('label.x069'),unknown:t('web.s514')}[value] || value || t('label.x073'));
  const table = (target, headers, rows) => {
    const wrapper=document.createElement('div');wrapper.className='table';wrapper.style.overflow='auto';wrapper.style.maxHeight='360px';
    const tab=document.createElement('table'),head=document.createElement('thead'),header=document.createElement('tr'),body=document.createElement('tbody');
    for(const value of headers)appendText(header,'th',value);head.append(header);tab.append(head,body);
    for(const values of rows) {const row=document.createElement('tr');for(const value of values)appendText(row,'td',value);body.append(row);}
    wrapper.append(tab);target.append(wrapper);
  };
  for(const detail of (report.pe_details || []).slice(0,8)) {
    for(const [kind,title,scope] of [['imports','imports','imports_scope'],['resources','resources','resources_scope'],['overlay','overlay','overlay_scope']]) {
      const data=detail[kind] || {}, node=card(label(title));
      appendText(node,'p',label(scope));appendText(node,'p',label('status')+': '+metadataStatus(data.status));
      appendText(node,'p',(data.reasons || []).join(', '));
      if(kind==='imports') {
        const rows=[];
        for(const library of (data.entries || []).slice(0,256)) {
          for(const fn of (library.functions || [])) {if(rows.length>=500)break;rows.push([library.dll,fn.kind==='name' ? fn.name : '#'+fn.ordinal]);}
          if(rows.length>=500)break;
        }
        table(node,[label('library'),label('function')],rows);
      } else if(kind==='resources') {
        table(node,[label('path'),label('offset'),label('bytes')],(data.entries || []).slice(0,200).map(item=>[(item.path || []).map(p=>p.name ?? p.id).join('/'),item.file_offset ?? t('label.x073'),item.bytes]));
      } else {
        table(node,[label('offset'),label('bytes')],(data.entries || []).slice(0,256).map(item=>[item.file_offset,item.bytes]));
        appendText(node,'p',label('certificates')+': '+(data.certificate_entries || []).length+' · '+label('overlay_bytes')+': '+(data.overlay_bytes ?? t('label.x073')));
      }
      if(kind!=='overlay')appendText(node,'p',label('display_limit'));
    }
  }
  if(report.pe_details_partial)appendText(card(label('pe_details')),'p',label('snapshot_limit'));
  const indicators=report.indicators, node=card(label('indicators'));
  appendText(node,'p',label('indicators_scope'));
  if(!indicators) {appendText(node,'p',label('no_capture'));return;}
  appendText(node,'p',label('status')+': '+metadataStatus(indicators.status));appendText(node,'p',(indicators.reasons || []).join(', '));
  const items=(indicators.indicators || []);
  table(node,[label('type'),label('value'),label('source_offset')],items.slice(0,200).map(item=>[item.type,item.value,(item.sources || []).slice(0,8).map(source=>String(source.source_step || '')+' @ '+(source.byte_offset ?? t('label.x073'))).join('; ')]));
  appendText(node,'p',label('indicator_display_limit'));
  const actions=document.createElement('div');actions.className='actions';
  actions.append(action(label('copy'),async()=>{await navigator.clipboard.writeText(JSON.stringify(indicators,null,2));message(label('copied'));}),
                 action(label('export'),async()=>{await downloadLogFile('/api/jobs/'+encodeURIComponent(ident)+'/indicators','Indikatoren-'+ident+'.json');}));
  node.append(actions);
}
