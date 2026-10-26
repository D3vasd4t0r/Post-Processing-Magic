"""Executable job-view state regressions using synthetic DOM and API responses only."""
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'forensic_app' / 'web' / 'job-views.js'


def test_job_views_preserve_state_and_source_download_boundaries(tmp_path):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required for the executable web regression')
    harness = tmp_path / 'job-views-check.cjs'
    harness.write_text(HARNESS, encoding='utf-8')
    result = subprocess.run(
        [node, str(harness), str(SCRIPT)], cwd=tmp_path,
        capture_output=True, text=True, encoding='utf-8', timeout=20, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS job views:' in result.stdout


HARNESS = r"""
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
class Element{
 constructor(tag='div'){this.tagName=tag;this.children=[];this.listeners={};this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.checked=true;this.scrollTop=0;this.scrollHeight=400;this.clientHeight=100;this.dataset={};this.attributes={};this.classList={toggle:()=>{}};}
 append(...items){this.children.push(...items);if(this.tagName==='select'&&!this.value&&items[0])this.value=items[0].value;}
 replaceChildren(...items){this.children=[];if(this.tagName==='select')this.value='';this.append(...items);}
 setAttribute(name,value){this.attributes[name]=value;}
 addEventListener(event,fn){this.listeners[event]=fn;}
 click(){if(this.tagName==='a')downloads.push(this.href);}
 remove(){}
}
const nodes={},downloads=[],calls=[],timers=[];
const byId=id=>nodes[id]??=(new Element(id==='log-job'?'select':'div'));
const jobs=[{id:'a1',status:'succeeded',case_number:'CASE',device_name:'DEVICE',filename:'one.zip',created_at:'2026-10-25',mode_name:'Medium'},
{id:'b2',status:'running',case_number:'CASE',device_name:'DEVICE',filename:'two.zip',created_at:'2026-10-26',mode_name:'Medium'}];
let resolver=null;
const context={byId,document:{createElement:tag=>new Element(tag),body:new Element()},t:(key,p)=>key+JSON.stringify(p||{}),setUiText:(node,fn)=>node.textContent=fn(),
 token:'own',currentPage:'logs',activeJobId:null,run:fn=>fn(),downloadLogFile:async(...args)=>calls.push(args),
 setTimeout:fn=>{timers.push(fn);return timers.length},clearTimeout:()=>{},URLSearchParams,console,
 api:async(path,method)=>{calls.push([path,method]);if(resolver)return resolver(path,method);
  if(path.startsWith('/api/jobs?'))return {jobs,total:2};
  if(path.endsWith('/source'))return {kind:'local',available:true,path:'C:/original.zip',filename:'original.zip'};
  if(path.endsWith('/download-ticket'))return {url:'/api/results/own-ticket'};
  const item=jobs.find(item=>path==='/api/jobs/'+item.id);if(item)return {...item,command:'OWN COMMAND',log_tail:'OWN LOG',work_directory:'C:/work/'+item.id,result_available:true,report_available:true};
  throw new Error(path);
 }};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[2],'utf8'),context);
(async()=>{
 await context.loadJobLogs();assert.equal(byId('log-job').children.length,2);assert.match(byId('log-job').children[0].textContent,/CASE.*DEVICE.*ZIP.*2026-10-25.*Medium.*a1/);
 assert.equal(byId('log-job-output').textContent,'OWN COMMAND\n\nOWN LOG');assert.equal(byId('log-work-directory').textContent,'C:/work/a1');
 byId('log-job-output').scrollTop=50;byId('log-job-output').listeners.scroll();assert.equal(byId('log-follow').attributes['aria-pressed'],'false');await context.loadSelectedLog();assert.equal(byId('log-job-output').scrollTop,50);
 byId('log-follow').listeners.click();assert.equal(byId('log-follow').attributes['aria-pressed'],'true');assert.equal(byId('log-job-output').scrollTop,400);
 let resolveOld;resolver=()=>new Promise(resolve=>resolveOld=resolve);byId('log-job').value='b2';const stale=context.loadSelectedLog();assert.equal(byId('log-job-output').textContent,'');
 context.clearJobViewTimers();resolveOld({...jobs[1],command:'STALE',log_tail:'STALE'});await stale;assert.equal(byId('log-job-output').textContent,'');
 resolver=null;context.currentPage='results';await context.loadResultJobs();assert.equal(byId('results-list').children.length,2);
 await context.loadSelectedResult('a1');assert.equal(byId('result-source-download').hidden,true);assert.equal(byId('result-source-path').textContent,'C:/original.zip');
 const beforeLocal=calls.length;await byId('result-source-download').listeners.click();assert.equal(downloads.length,0);assert.equal(calls.length,beforeLocal);
 assert(!calls.some(([path])=>path.endsWith('/a1/source/download-ticket')));
 await byId('result-download').listeners.click();assert.deepEqual(downloads,['/api/results/own-ticket']);
 resolver=async(path)=>path.endsWith('/source')?{kind:'upload',available:true,filename:'upload.zip'}:{...jobs[0],result_available:false,report_available:true,output_available:true};
 await context.loadSelectedResult('a1');assert.equal(byId('result-source-download').hidden,false);assert.equal(byId('result-archive').disabled,false);
 resolver=async(path)=>({url:'/api/sources/own-source'});await byId('result-source-download').listeners.click();assert.equal(downloads[1],'/api/sources/own-source');
 let resolves=[];resolver=()=>new Promise(resolve=>resolves.push(resolve));const staleResult=context.loadSelectedResult('b2');context.clearJobViewTimers();context.currentPage='logs';resolves[0]({...jobs[1],result_available:true});resolves[1]({kind:'local',path:'C:/STALE'});await staleResult;assert.notEqual(byId('result-source-path').textContent,'C:/STALE');
 context.clearJobViewTimers();console.log('PASS job views: dropdown, raw terminal, manual scroll, stale guards, distinct case rows, local reference only, ZIP/source streaming tickets, explicit archive');
})().catch(e=>{console.error(e);process.exitCode=1});

"""
