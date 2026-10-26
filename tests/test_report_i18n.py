"""Metadata report translation and immutable historical projection."""
import copy
import html
from html.parser import HTMLParser
from string import Formatter

import pytest

from forensic_app.artifacts import metadata_report, render_report
from forensic_app.report_i18n import ReportText, catalog


class ReportElements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags=[]
    def handle_starttag(self,tag,attrs):
        self.tags.append((tag,dict(attrs)))


def test_catalog_key_and_named_placeholder_parity():
    de,en=catalog('de'),catalog('en')
    assert de.keys()==en.keys()
    for key in de:
        def params(value):
            return {name for _,name,_,_ in Formatter().parse(value) if name is not None}
        assert params(de[key])==params(en[key]),key
        assert all(name.isidentifier() for name in params(de[key]))
    assert ReportText('fr').locale=='de'
    assert ReportText('en')('heading',workspace='Own')=='Own – Completion report'
    text=ReportText('en');text.messages={}
    assert text('title')=='Abschlussbericht'
    assert not any(key.startswith(('inspector.','extended.','observation.','coverage.','inventory.group.')) for key in de)


@pytest.mark.parametrize('locale',['de','en'])
def test_locale_user_text_escaping_independent_print_and_metadata_only(locale):
    own='<script>Fall & Modus</script>'
    report={'configuration':{'workspace':'forensics','locale':locale,'case_number':own,'device_name':own,
                            'mode':{'name':own},'commands':[{'command':'SECRET_CLI','tool':{'name':'Own','version':'1','sha256':'b'*64}}]},
            'command_runs':[{'index':1,'exit_code':0}],
            'files':[{'path':own,'bytes':10}], 'input':{'sha1':'a'*40,'sha256':'b'*64},
            'finding_summaries':[{'contents':'SECRET_FINDING'}], 'log_tail':'SECRET_TERMINAL'}
    before=copy.deepcopy(report);page=render_report(report)
    parsed=ReportElements();parsed.feed(page)
    assert report==before and ('html',{'lang':locale}) in parsed.tags
    assert not any(tag=='script' for tag,_ in parsed.tags)
    assert html.escape(own) in page
    assert 'b'*64 in page and 'a'*40 in page
    assert page.count('class="print-content"')==page.count('<details open>')>5
    assert '@media print{details{display:none}.print-content{display:block}' in page
    assert ('Completion report' if locale=='en' else 'Abschlussbericht') in page
    assert all(secret not in page for secret in ('SECRET_CLI','SECRET_FINDING','SECRET_TERMINAL'))


def test_inventory_and_archive_notes_localized_without_rewriting_snapshot():
    report={'configuration':{'locale':'en'},'archive':{'created':True,'embedded':True},
            'input_inventory':{'schema_version':2,'files_metadata':[{'path':'C/Own <name>','bytes':10}],
                               'files':1,'directories':1,'bytes':10,'complete':False,
                               'partial_reasons':['entry_limit'],'paths_truncated':True}}
    before=copy.deepcopy(report);page=render_report(report)
    assert 'Partial recording: Entry limit' in page
    assert 'no self-referential archive hash' in page
    assert 'C/Own &lt;name&gt;' in page
    assert report==before


def test_legacy_classification_is_not_republished_or_recomputed():
    report={'configuration':{},'input_inventory':{'groups':{'evtx':{'label':'SECRET_CLASSIFICATION','samples':['secret']}},'files':3,'bytes':10}}
    clean=metadata_report(report)
    assert clean['input_inventory']['files']==3
    assert clean['input_inventory']['files_metadata']==[]
    assert 'SECRET_CLASSIFICATION' not in render_report(report)
    assert '<html lang="de">' in render_report(report)
