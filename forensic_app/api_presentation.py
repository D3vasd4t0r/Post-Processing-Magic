"""Allowlisted UI JSON projection. Never translate stored configuration or raw data.

This module has no storage access. Callers must keep SSE, report, download,
export and diagnostics responses outside their JSON middleware buffer.
"""
import json
import re
from functools import lru_cache
from pathlib import Path

from forensic_app.app_errors import ErrorText
from forensic_app.app_errors import catalog as error_catalog

_FIXED = frozenset({
    '/api/jobs', '/api/jobs/catalog', '/api/settings/tools',
    '/api/settings/tools/check', '/api/settings/workspace',
    '/api/settings/storage', '/api/settings/storage/scan',
    '/api/settings/cleanup/preview', '/api/settings/configuration/preview',
})
_JOB = re.compile(r'/api/jobs/[^/]+(?:/(?:explorer|source))?\Z')
_TOOL = re.compile(r'/api/settings/tools/[^/]+\Z')


def is_presentation_path(path):
    """Only known JSON UI routes; query strings do not alter the route contract."""
    route=path.split('?',1)[0].rstrip('/')
    if any(part in {'export','download','download-ticket','report','diagnostics','log','events','raw'} for part in route.split('/')):
        return False
    if route in _FIXED:
        return True
    if _JOB.fullmatch(route):
        # Single-segment action names are not job-status resources.
        return route.rsplit('/',1)[-1] not in {'local','browse'}
    return bool(_TOOL.fullmatch(route) and route.rsplit('/',1)[-1] not in {'browse'})


@lru_cache(maxsize=2)
def catalog(locale):
    language=locale if locale in ('de','en') else 'de'
    return json.loads((Path(__file__).parent/'locales'/f'presentation.{language}.json').read_text(encoding='utf-8'))


class Presentation:
    def __init__(self,locale):
        self.locale=locale
        self.de=catalog('de')
        self.messages=catalog(locale)

    def exact(self,value,prefix):
        if not isinstance(value,str):
            return value
        for key,original in self.de.items():
            if key.startswith(prefix) and value==original:
                return self.messages.get(key,original)
        return value

    def application_error(self,value):
        if isinstance(value,ErrorText):
            return value.localized(self.locale)
        if isinstance(value,str):
            for code,original in error_catalog('de').items():
                if value==original and '{' not in original:
                    return error_catalog(self.locale).get(code,original)
        return value

    def phase(self,value):
        translated=self.exact(value,'phase.')
        if translated!=value or not isinstance(value,str):
            return translated
        match=re.fullmatch(r'Lokale ZIP hashen: ([0-9]+\.[0-9]+)/([0-9]+\.[0-9]+) GiB',value)
        if match:
            return self.messages['phase.local_hash'].format(read=match[1],total=match[2])
        return value

    def job(self,job):
        if not isinstance(job,dict):
            return
        if 'phase' in job:
            job['phase']=self.phase(job['phase'])
        detail=job.get('error_detail')
        if isinstance(detail,dict):
            if 'phase' in detail:
                detail['phase']=self.phase(detail['phase'])
            if 'recommendation' in detail:
                detail['recommendation']=self.exact(detail['recommendation'],'recommendation.')
            if isinstance(detail.get('error_code'),str) and isinstance(detail.get('error_params',{}),dict):
                try:
                    message=ErrorText(detail['error_code'],**detail.get('error_params',{})).localized(self.locale)
                except (KeyError,ValueError,TypeError):
                    pass  # Unknown historical codes/parameters remain canonical data.
                else:
                    detail['message']=message
                    if 'error' in job:
                        job['error']=message


def present_response(path,body,locale):
    """Copy/project known UI metadata only; raw/unknown routes are identity calls."""
    if locale!='en' or not is_presentation_path(path) or not isinstance(body,(dict,list)):
        return body
    route=path.split('?',1)[0].rstrip('/')
    def clone(value):
        if isinstance(value,dict):
            return {key:clone(item) for key,item in value.items()}
        if isinstance(value,list):
            return [clone(item) for item in value]
        return value
    result=clone(body)
    if not isinstance(result,dict):
        return result
    p=Presentation(locale)
    if route=='/api/settings/configuration/preview':
        for field in ('errors','warnings'):
            if isinstance(result.get(field),list):
                result[field]=[p.application_error(value) for value in result[field]]
    elif route=='/api/jobs/catalog':
        for mode in result.get('modes',[]):
            if isinstance(mode,dict) and 'reason' in mode:
                mode['reason']=p.application_error(mode['reason'])
    elif route=='/api/jobs':
        for job in result.get('jobs',[]):
            p.job(job)
    elif route.endswith('/explorer') and route.startswith('/api/jobs/'):
        for field in ('reason','message'):
            if field in result:
                result[field]=p.application_error(p.exact(result[field],'explorer.'))
    elif route.startswith('/api/jobs/'):
        p.job(result)
    elif route.startswith('/api/settings/tools'):
        tools=result.get('tools',[result])
        for tool in tools:
            if isinstance(tool,dict) and 'message' in tool:
                tool['message']=p.exact(tool['message'],'path.')
    elif route=='/api/settings/workspace':
        if 'note' in result:
            result['note']=p.exact(result['note'],'workspace.')
    elif route.startswith('/api/settings/storage'):
        scan=result.get('scan')
        if isinstance(scan,dict):
            for area in scan.get('areas',[]):
                if isinstance(area,dict) and 'label' in area:
                    area['label']=p.exact(area['label'],'storage.')
    elif route=='/api/settings/cleanup/preview':
        for field in ('label','note','root'):
            if field in result:
                result[field]=p.exact(result[field],'cleanup.')
    return result
