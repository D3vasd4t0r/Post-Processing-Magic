import copy
from html.parser import HTMLParser

import pytest

from forensic_app.artifacts import render_report


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags=[]
    def handle_starttag(self,tag,attrs):
        self.tags.append((tag,dict(attrs)))


@pytest.mark.parametrize('workspace',['forensics'])
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


def test_print_content_exists_independently_of_details():
    page=render_report({'configuration':{},'files':[]})
    parsed=Elements();parsed.feed(page)
    assert len([a for t,a in parsed.tags if t=='div' and a.get('class')=='print-content']) == len([a for t,a in parsed.tags if t=='section'])
    assert '@media print{details{display:none}.print-content{display:block}' in page
