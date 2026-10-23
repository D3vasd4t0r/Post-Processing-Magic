import copy
from html.parser import HTMLParser
from pathlib import Path

import pytest

from forensic_app.artifacts import render_report
from forensic_app.jobs import LocalJob


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags=[]
    def handle_starttag(self,tag,attrs):
        self.tags.append((tag,dict(attrs)))


@pytest.mark.parametrize('workspace',['forensics','malware'])
def test_every_report_section_has_native_open_disclosure_without_mutating_report(workspace):
    report={'configuration':{'workspace':workspace,'mode':{'name':'<script>own</script>'}},'files':[]}
    original=copy.deepcopy(report)
    page=render_report(report)
    parsed=Elements();parsed.feed(page)
    sections=[a for t,a in parsed.tags if t=='section']
    details=[a for t,a in parsed.tags if t=='details']
    summaries=[a for t,a in parsed.tags if t=='summary']
    assert len(sections)==len(details)==len(summaries)>5
    assert all('open' in attrs for attrs in details)
    assert not any(tag=='script' for tag,_ in parsed.tags)
    assert '&lt;script&gt;own&lt;/script&gt;' in page
    assert report==original


def test_high_compression_is_only_browser_preselection():
    parsed=Elements();parsed.feed(Path('forensic_app/web/index.html').read_text(encoding='utf-8'))
    checkbox=next(attrs for tag,attrs in parsed.tags if tag=='input' and attrs.get('id')=='allow-high-compression')
    assert 'checked' in checkbox
    # Existing API clients and snapshots retain their explicit/legacy choice.
    assert LocalJob(mode_id='own',path='own.zip').allow_high_compression is False


def test_print_content_exists_independently_of_details():
    page=render_report({'configuration':{},'files':[]})
    parsed=Elements();parsed.feed(page)
    assert len([a for t,a in parsed.tags if t=='div' and a.get('class')=='print-content']) == len([a for t,a in parsed.tags if t=='section'])
    assert '@media print{details{display:none}.print-content{display:block}' in page
