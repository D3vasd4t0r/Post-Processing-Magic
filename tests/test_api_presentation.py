"""Presentation must never turn raw JSON/configuration into translated data."""
import copy
from string import Formatter

import pytest

from forensic_app.api_presentation import catalog, is_presentation_path, present_response
from forensic_app.app_errors import ErrorText


def test_catalog_keys_and_named_parameters():
    de,en=catalog('de'),catalog('en')
    assert de.keys()==en.keys()
    for key in de:
        params=lambda text:{name for _,name,_,_ in Formatter().parse(text) if name is not None}
        assert params(de[key])==params(en[key])
        assert all(name.isidentifier() for name in params(de[key]))
    assert catalog('invalid')==de


@pytest.mark.parametrize('path',[
    '/api/jobs/own/report?format=json','/api/jobs/own/report?format=html',
    '/api/jobs/own/diagnostics','/api/jobs/own/log','/api/jobs/own/events',
    '/api/jobs/own/download','/api/jobs/own/download-ticket','/api/settings/configuration/export',
    '/api/settings/tools/export','/api/settings/cleanup/apply','/api/results/own',
    '/api/settings/modes','/api/settings/malware','/api/settings/configuration/apply',
    '/api/diagnostics/preview','/unknown',
    '/api/jobs/own/preview','/api/jobs/own/csv','/api/jobs/own/viewer',
    '/api/jobs/own/summary','/api/jobs/own/findings','/api/jobs/own/source/download-ticket',
])
def test_raw_exports_downloads_and_unknown_routes_are_identity(path):
    raw={'phase':'Abgeschlossen','message':'Programmdatei gefunden','scope_note':'Raw inventory scope'}
    assert not is_presentation_path(path)
    assert present_response(path,raw,'en') is raw


def test_job_only_explicit_metadata_translated_without_touching_logs_or_config():
    own='Abgeschlossen'
    raw={'phase':'Abgeschlossen','filename':own,'mode_name':own,'command':own,'log_tail':own,
         'configuration':{'phase':own,'label':'Eingänge'},'error':'Original <raw>',
         'error_detail':{'phase':'ZIP prüfen und entpacken','recommendation':catalog('de')['recommendation.0'],
                         'message':'Original <raw>','traceback':'ZIP prüfen und entpacken'},
         'input_inventory':{'scope_note':'Raw inventory scope',
                            'groups':{'own':{'label':'Raw file group',
                                             'samples':['Abgeschlossen/<own>']}},
                            'partial_reasons':['entry_limit','unknown_reason']}}
    before=copy.deepcopy(raw);result=present_response('/api/jobs/own',raw,'en')
    assert raw==before and result is not raw
    assert result['phase']=='Completed'
    assert result['error_detail']['phase']=='Check and extract ZIP'
    assert result['error_detail']['recommendation']=='Check details and the last tool output in Logs.'
    for key in ['filename','mode_name','command','log_tail','configuration','error']:
        assert result[key]==raw[key]
    assert result['error_detail']['message']==raw['error_detail']['message']
    assert result['error_detail']['traceback']==raw['error_detail']['traceback']
    assert result['input_inventory'] == raw['input_inventory']
    assert present_response('/api/jobs/own',raw,'de') is raw
    assert present_response('/api/jobs/own',raw,'fr') is raw


def test_phase_named_parameters_and_history_list():
    raw={'jobs':[{'phase':'Lokale ZIP hashen: 1.0/3.0 GiB','filename':'Lokale ZIP hashen: 1.0/3.0 GiB'},
                 {'phase':'Own running label'}], 'modes':[{'name':'Abgeschlossen'}]}
    result=present_response('/api/jobs',raw,'en')
    assert result['jobs'][0]['phase']=='Hash local ZIP: 1.0/3.0 GiB'
    assert result['jobs'][0]['filename']==raw['jobs'][0]['filename']
    assert result['jobs'][1]['phase']=='Own running label'
    assert result['modes']==raw['modes']


def test_structured_job_error_only_when_code_is_known():
    code='error.60d41cc15b14'
    raw={'error_detail':{'error_code':code,'error_params':{},'message':str(ErrorText(code))},'error':str(ErrorText(code))}
    result=present_response('/api/jobs/own',raw,'en')
    assert result['error_detail']['message']==ErrorText(code).localized('en')
    assert result['error']==result['error_detail']['message']
    unknown={'error_detail':{'error_code':'unknown','message':'Own diagnostic'}}
    assert present_response('/api/jobs/own',unknown,'en')==unknown


def test_catalog_and_explorer_use_explicit_known_app_errors():
    code='error.60d41cc15b14'
    raw={'modes':[{'name':'Abgeschlossen','reason':ErrorText(code)},{'reason':'Own <message>'}]}
    result=present_response('/api/jobs/catalog',raw,'en')
    assert result['modes'][0]['reason']==ErrorText(code).localized('en')
    assert result['modes'][0]['name']=='Abgeschlossen'
    assert result['modes'][1]['reason']=='Own <message>'
    response=present_response('/api/jobs/own/explorer',{'reason':catalog('de')['explorer.available'],'path':'Abgeschlossen'},'en')
    assert response['reason']==catalog('en')['explorer.available'] and response['path']=='Abgeschlossen'


@pytest.mark.parametrize('path,body,field,key',[
    ('/api/settings/tools/check',{'message':'Programmdatei gefunden','name':'Programmdatei gefunden'},'message','path.file'),
    ('/api/settings/workspace',{'note':catalog('de')['workspace.note'],'path':'Eingänge'},'note','workspace.note'),
    ('/api/settings/cleanup/preview',{'label':'Cache leeren','note':catalog('de')['cleanup.note.cache']},'label','cleanup.cache'),
])
def test_known_ui_fields(path,body,field,key):
    before=copy.deepcopy(body);result=present_response(path,body,'en')
    assert body==before and result[field]==catalog('en')[key]
    for raw_key in ('name','path','rows','sheets'):
        if raw_key in body:
            assert result[raw_key]==body[raw_key]
    if body.get('partial_reason'):
        assert result['partial_reason']=='Row limit'


def test_storage_and_tool_list_only_expected_locations():
    body={'scan':{'areas':[{'label':'Eingänge','path':'Eingänge'}]},'locations':[{'label':'Eingänge'}]}
    out=present_response('/api/settings/storage/scan',body,'en')
    assert out['scan']['areas'][0]=={'label':'Inputs','path':'Eingänge'}
    assert out['locations']==body['locations']
    tools={'tools':[{'name':'Programmdatei gefunden','message':'Programmdatei gefunden','used_by':[{'message':'Programmdatei gefunden'}]}]}
    out=present_response('/api/settings/tools',tools,'en')
    assert out['tools'][0]['message']=='Program file found'
    assert out['tools'][0]['name']==tools['tools'][0]['name']
    assert out['tools'][0]['used_by']==tools['tools'][0]['used_by']


def test_removed_analysis_routes_are_not_projected():
    raw = {'phase':'Abgeschlossen', 'findings':[{'label':'Raw <payload>'}],
           'sha256':'a'*64, 'rows':[['Untranslated raw value']]}
    for suffix in ('summary', 'preview', 'csv', 'viewer', 'findings', 'indicators'):
        path = '/api/jobs/own/'+suffix
        assert not is_presentation_path(path)
        assert present_response(path, raw, 'en') is raw


def test_source_metadata_does_not_translate_user_paths_or_integrity():
    raw = {'source_kind':'local', 'path':'C:/Abgeschlossen/input.zip', 'filename':'Abgeschlossen.zip',
           'available':True, 'sha1':'b'*40, 'sha256':'a'*64}
    before = copy.deepcopy(raw)
    assert is_presentation_path('/api/jobs/own/source')
    assert present_response('/api/jobs/own/source', raw, 'en') == before
    assert raw == before


def test_configuration_preview_translates_hints_only():
    from forensic_app.app_errors import ErrorText
    source={'errors':[ErrorText('config.duplicate_name',kind='tools',name='Nutzer <raw>')],
            'warnings':[], 'changes':{'tools':{'added':['Nutzer <raw>']}}}
    projected=present_response('/api/settings/configuration/preview',source,'en')
    assert projected['errors']==['Duplicate name in tools: Nutzer <raw>']
    assert projected['changes']==source['changes']
    assert source['errors'][0]=='Doppelter Name in tools: Nutzer <raw>'
