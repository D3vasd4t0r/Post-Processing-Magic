"""Offline web localization: explicit source inventory and executable UI projections."""
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'forensic_app' / 'web'
LOCALES = ROOT / 'forensic_app' / 'locales'


def catalogs():
    return {locale: json.loads((LOCALES / f'web.{locale}.json').read_text(encoding='utf-8'))
            for locale in ('de', 'en')}


def test_catalog_and_named_parameter_parity():
    values = catalogs()
    assert values['de'].keys() == values['en'].keys()
    assert len(values['de']) > 300
    for key, german in values['de'].items():
        assert german and values['en'][key], key
        assert set(re.findall(r'\{([a-zA-Z][a-zA-Z0-9_]*)\}', german)) == set(
            re.findall(r'\{([a-zA-Z][a-zA-Z0-9_]*)\}', values['en'][key])), key
    assert values['en']['run.total'] == 'Total: {completed} of {total} commands executed'


def test_explicit_keys_cover_zip_workspace_and_dialogs():
    values = catalogs()['de']
    source = (WEB / 'index.html').read_text(encoding='utf-8')
    scripts = source + ''.join(p.read_text(encoding='utf-8') for p in WEB.glob('*.js'))
    for key in re.findall(r"\bt\(['\"]([^'\"]+)['\"]\)", scripts):
        assert key in values, key
    for key in re.findall(r'data-i18n(?:-[\w-]+)?="([^"]+)"', source):
        assert key in values, key
    for key in re.findall(r"jvLabel\([^,]+,['\"]([^'\"]+)['\"]", scripts):
        assert key in values, key
    assert 'jobview.page' in values and 'jobview.empty' in values
    assert 'MutationObserver' not in (WEB / 'i18n.js').read_text(encoding='utf-8')
    assert 'value="Medium"' in source


class Inventory(HTMLParser):
    def __init__(self):
        super().__init__()
        self.nodes = []
        self.stack = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        node = {'tag': tag, 'attrs': attrs, 'text': ''}
        self.nodes.append(node)
        if tag not in {'meta', 'input', 'br', 'link', 'hr'}:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]['tag'] == tag:
                self.stack = self.stack[:index]
                break

    def handle_data(self, data):
        if self.stack:
            self.stack[-1]['text'] += data


def test_static_source_inventory_has_no_unmarked_visible_german():
    inventory = Inventory()
    inventory.feed((WEB / 'index.html').read_text(encoding='utf-8').split('<script src="/i18n.js">')[0])
    unmarked = []
    for node in inventory.nodes:
        if node['tag'] in {'style', 'script', 'code', 'title', 'path', 'circle'}:
            continue
        text = node['text'].strip()
        if text and re.search('[äöüßÄÖÜ]|[a-z]+ [a-z]+', text) and 'data-i18n' not in node['attrs']:
            unmarked.append(text)
    assert not unmarked


def test_executable_locale_persistence_main_paths_and_raw_integrity(tmp_path):
    run_web_harness(tmp_path, NODE_HARNESS)


def run_web_harness(tmp_path, harness):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the executable browser-logic harness')
    inventory = Inventory()
    html = (WEB / 'index.html').read_text(encoding='utf-8')
    inventory.feed(html.split('<script src="/i18n.js">')[0])
    payload = {'nodes': inventory.nodes, 'catalogs': catalogs(),
               'i18n': (WEB / 'i18n.js').read_text(encoding='utf-8'),
               'main': html.split('<script>')[1].split('</script>')[0],
               'workspace': (WEB / 'workspace.js').read_text(encoding='utf-8'),
               'jobs': (WEB / 'job-views.js').read_text(encoding='utf-8')}
    data = tmp_path / 'source.json'
    data.write_text(json.dumps(payload), encoding='utf-8')
    script = tmp_path / 'check.cjs'
    script.write_text(harness, encoding='utf-8')
    result = subprocess.run([node, str(script), str(data)], capture_output=True, text=True,
                            encoding='utf-8', timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'ZIP workspace, persistence, drafts and raw data verified' in result.stdout


NODE_HARNESS = r"""
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
class Element {
  constructor(tag='div',attrs={},text='') {this.tagName=tag;this.attrs={...attrs};this.textContent=text;this.value=attrs.value||'';this.id=attrs.id||'';this.hidden='hidden' in attrs;this.disabled='disabled' in attrs;this.checked='checked' in attrs;this.children=[];this.listeners={};this.dataset={};this.style={};this.files=[];this.isConnected=true;const classes=new Set();this.classList={toggle:(key,on)=>{const active=on===undefined?!classes.has(key):on;if(active)classes.add(key);else classes.delete(key);return active;},add:key=>classes.add(key),remove:key=>classes.delete(key),contains:key=>classes.has(key)};}
  get options(){return this.children;} get selectedOptions(){return this.options.filter(n=>n.value===this.value);}
  setAttribute(k,v){this.attrs[k]=String(v);} getAttribute(k){return this.attrs[k]??null;} removeAttribute(k){delete this.attrs[k];}
  append(...items){this.children.push(...items);} replaceChildren(...items){this.children=[...items];this.textContent='';}
  addEventListener(k,fn){(this.listeners[k]??=[]).push(fn);} reset(){} focus(){} scrollIntoView(){} remove(){this.isConnected=false;} close(){this.open=false;} showModal(){this.open=true;} reportValidity(){return true;}
  querySelectorAll(){return [];} querySelector(){return null;}
}
const elements=input.nodes.map(n=>new Element(n.tag,n.attrs,n.text));
const ids=new Map(elements.filter(n=>n.id).map(n=>[n.id,n]));
const get=id=>{if(!ids.has(id))ids.set(id,new Element());return ids.get(id);};
for(const [select,values] of [['mode-effort',['schnell','Medium','langsam']]])get(select).children=values.map(v=>new Element('option',{value:v},v));
get('run-source-kind').value='upload';
const extra=new Map();
const doc={documentElement:{lang:'de'},body:new Element('body'),getElementById:get,addEventListener:()=>{},
 querySelectorAll:q=>q.includes('[data-i18n]')?elements.filter(n=>Object.keys(n.attrs).some(k=>k.startsWith('data-i18n'))):q==='[data-cleanup]'?elements.filter(n=>'data-cleanup' in n.attrs):[],
 querySelector:q=>{if(!extra.has(q))extra.set(q,new Element());return extra.get(q);},createElement:t=>new Element(t),createTextNode:text=>new Element('text',{},text)};
const local=new Map([['ppm-locale','en']]),session=new Map();
const store=map=>({getItem:k=>map.get(k)??null,setItem:(k,v)=>map.set(k,String(v)),removeItem:k=>map.delete(k)});
let prefs={locale:'de',onboarding_dismissed:false};let writes=[];let requests=[];
const opaque='schnell Fehler C:\\Verdächtig\\No output yet. <script>alert(1)</script>';
const tool={id:'tool1',name:opaque,path:'C:\\Fehler\\schnell.exe',message:'saved',kind:'file',used_by:[]};
async function fetch(url,opts={}) {requests.push([url,opts.method||'GET']);let body;
 if(url==='/synthetic-error') return {ok:false,status:400,json:async()=>({error_code:'unknown.synthetic',detail:opaque})};
 if(url.startsWith('/locales/web/'))body=input.catalogs[url.includes('/en.')?'en':'de'];
 else if(url==='/api/settings/interface') {if(opts.method==='PUT'){const patch=JSON.parse(opts.body);writes.push(patch);prefs={...prefs,...patch};}body={...prefs};}
 else if(url==='/api/system')body={version:'synthetic',mode:'local',administrator:true,storage:opaque,database:opaque,token_file:opaque};
 else if(url==='/api/settings/tools')body={tools:[tool]};
 else if(url==='/api/settings/modes')body={modes:[],availability:[],workspace_pattern:opaque};
 else if(url.startsWith('/api/jobs/catalog'))body={worker:false,modes:[],limits:{max_upload_bytes:1024**3,max_extract_bytes:1e12}};
 else throw Error('Unexpected API '+url);
 return {ok:true,status:200,json:async()=>JSON.parse(JSON.stringify(body))};
}
const context={document:doc,fetch,localStorage:store(local),sessionStorage:store(session),location:{hash:'',pathname:'/'},history:{replaceState:()=>{}},console,Intl,URL,URLSearchParams,Blob,TextDecoder,AbortController,crypto:require('crypto').webcrypto,setTimeout:()=>0,clearTimeout:()=>{},Option:function(text,value){return new Element('option',{value},text);},confirm:()=>false};
vm.createContext(context);vm.runInContext(input.i18n+'\n'+input.main+'\n'+input.workspace+'\n'+input.jobs,context);
async function evaluate(code){return vm.runInContext('(async()=>{'+code+'})()',context);}
(async()=>{
 await evaluate('await I18n.ready;');assert.equal(doc.documentElement.lang,'en');assert.equal(get('nav-settings').textContent,'Settings');
 await evaluate("token='synthetic';await connect();await navigate('overview');");
 assert.equal(doc.documentElement.lang,'de');assert.equal(get('nav-settings').textContent,'Einstellungen');
 get('tool-name').value=opaque;get('tool-path').value=tool.path;
 await evaluate("await navigate('settings');await showSettings('tools');");
 get('interface-locale').value='en';await get('interface-locale').listeners.change[0]();
 assert.equal(prefs.locale,'en');assert.equal(doc.documentElement.lang,'en');assert.equal(get('tool-name').value,opaque);assert.equal(get('tool-path').value,tool.path);assert.equal(get('editor-title').textContent,'Add tool');
 const names=get('tools-list').children.map(n=>n.children[0].textContent);assert.deepEqual(names,[opaque]);
 await evaluate("await navigate('settings');await showSettings('modes');editMode({id:'draft',name:'schnell Fehler draft',description:'raw desc',evidence_format:'ZIP',effort:'Medium',extract_folder:'Targets',output_folder:'RawOutput',steps:[{id:'draft-step',name:'raw step',type:'tool',tool_id:'tool1',parameters:'--raw schnell Fehler',working_directory:'.',timeout_seconds:42}]});");
 get('interface-locale').value='de';await get('interface-locale').listeners.change[0]();
 assert.equal(get('mode-name').value,'schnell Fehler draft');assert.equal(get('mode-output').value,'RawOutput');assert.equal(await evaluate('return modeSteps[0].parameters;'),'--raw schnell Fehler');assert.equal(await evaluate('return modeSteps[0].timeout_seconds;'),42);
 await evaluate("let error;try{await api('/synthetic-error');}catch(e){error=e.message;}if(error!=="+JSON.stringify(opaque)+")throw new Error('raw error was changed');");
 await evaluate("const raw=document.createElement('pre');raw.id='raw';document.body.append(raw);setUiText(raw,()=> 'schnell Fehler C:\\\\schnell <b>raw</b>');globalThis.rawNode=raw;const label=document.createElement('p');document.body.append(label);setUiText(label,()=>t('run.total',{completed:2,total:3}),true);globalThis.boundLabel=label;await I18n.setLocale('de');refreshUiText();");
 assert.equal(context.rawNode.textContent,'schnell Fehler C:\\schnell <b>raw</b>');assert.equal(context.boundLabel.textContent,'Gesamt: 2 von 3 Befehlen ausgeführt');
 await evaluate("await I18n.setLocale('en');");
 assert.equal(doc.documentElement.lang,'en');assert.ok(writes.some(p=>p.locale==='en'));assert.ok(writes.some(p=>p.locale==='de'));
 assert.equal(requests.filter(([url,method])=>method!=='GET'&&url!=='/api/settings/interface').length,0);
 console.log('ZIP workspace, persistence, drafts and raw data verified');
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
