"""Report localization is a presentation projection, never a finding rewrite."""
import copy
import html
import json
from html.parser import HTMLParser
from pathlib import Path
from string import Formatter

import pytest

from forensic_app.artifacts import render_report
from forensic_app.finding_summary import summarize_finding
from forensic_app.report_i18n import ReportText, catalog
from forensic_app.static_analysis import SCOPE, render_static_report, run_static


class ReportElements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags=[]
    def handle_starttag(self,tag,attrs):
        self.tags.append((tag,dict(attrs)))


def finding(kind='metadata'):
    return {'scope':SCOPE,'inspection':kind,'input':{'bytes':10,'sha1':'a'*40,'sha256':'b'*64},
            'findings':{'inspected_bytes':10,'file_bytes':10,'partial':False,
                        'entropy_bits_per_byte':2.0,'limitation':'Entropie nur über das erste MiB; hohe Entropie allein ist kein Malware-Nachweis.'}}


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


@pytest.mark.parametrize('workspace',['forensics','malware'])
@pytest.mark.parametrize('locale',['de','en'])
def test_aggregate_locale_data_integrity_and_independent_print(workspace,locale):
    own='<script>Fall & Modus</script>'
    report={'configuration':{'workspace':workspace,'locale':locale,'case_number':own,'device_name':own,
                            'mode':{'name':own},'commands':[{'type':'powershell','command':own,
                            'tool':{'name':own,'path':own,'sha256':'b'*64}}]},
            'finding_summaries':[summarize_finding(finding())],
            'files':[{'path':own,'bytes':10}], 'input':{'sha1':'a'*40,'sha256':'b'*64}}
    before=copy.deepcopy(report);page=render_report(report)
    parsed=ReportElements();parsed.feed(page)
    assert report==before
    assert ('html',{'lang':locale}) in parsed.tags
    assert not any(tag=='script' for tag,_ in parsed.tags)
    assert html.escape(own) in page
    assert 'b'*64 in page and 'a'*40 in page
    assert page.count('class="print-content"')==page.count('<details open>')>5
    assert '@media print{details{display:none}.print-content{display:block}' in page
    assert ('Completion report' if locale=='en' else 'Abschlussbericht') in page
    assert ('Entropy of the first 1 MiB' if locale=='en' else 'Entropie der ersten 1 MiB') in page
    assert ('high entropy alone does not prove malware' if locale=='en' else 'hohe Entropie allein') in page
    assert ('Bytes inspected' if locale=='en' else 'Gelesene Bytes') in page


def test_legacy_report_default_and_unknown_metadata_preserved():
    report={'configuration':{},'finding_summaries':[summarize_finding(finding())]}
    report['finding_summaries'][0]['inspector']['limitations']=['Own <scope> remains unchanged']
    assert '<html lang="de">' in render_report(report)
    english=copy.deepcopy(report);english['configuration']['locale']='en'
    assert 'Own &lt;scope&gt; remains unchanged' in render_report(english)
    assert '<html lang="de">' in render_report(report)


def test_inventory_and_archive_notes_localized_without_rewriting_snapshot():
    report={'configuration':{'locale':'en'},'archive':{'created':True,'note':catalog('de')['archive_embedded']},
            'input_inventory':{'groups':{'evtx':{'label':catalog('de')['inventory.group.evtx'],
                              'files':1,'bytes':10,'samples':['C/Own <evtx>']}},
                              'scope_note':catalog('de')['inventory.scope'],'complete':False,
                              'partial_reasons':['entry_limit','unknown_code']}}
    before=copy.deepcopy(report);page=render_report(report)
    assert 'Windows event logs (.evtx)' in page
    assert 'Partial recording: Entry limit, unknown_code' in page
    assert 'no self-referential archive hash' in page
    assert 'C/Own &lt;evtx&gt;' in page
    assert report==before


@pytest.mark.parametrize('locale',['de','en'])
def test_standalone_preserves_raw_json_and_complete_print(locale):
    raw=finding();raw['findings']['own']='<script>unsafe</script>'
    raw['summary']=summarize_finding(raw);before=copy.deepcopy(raw)
    page=render_static_report(raw,locale)
    assert raw==before
    assert html.escape(json.dumps(raw,ensure_ascii=False,indent=2)) in page
    assert '<html lang="'+locale+'">' in page
    assert '<script>' not in page
    assert page.count('class="print-content"')==page.count('<details open>')==2
    assert ('Static inspection' if locale=='en' else 'Statische Prüfung') in page
    assert ('Metadata and entropy' if locale=='en' else 'Metadaten und Entropie') in page


@pytest.mark.parametrize('locale',['de','en',None])
def test_run_static_uses_only_frozen_plan_locale_and_retains_json(tmp_path,locale):
    (tmp_path/'Sample').mkdir();(tmp_path/'Sample/input.bin').write_bytes(b'%PDF-1.7\nsynthetic\n')
    plan={'inspector':'metadata','id':'own','mode':{'evidence_format':'PDF','output_folder':'Results'},
          'static_input':{'bytes':19,'sha256':'a'*64}}
    if locale is not None:
        plan['locale']=locale
    before=copy.deepcopy(plan);emitted=[]
    assert run_static(plan,tmp_path,lambda:None,emitted.append)==0
    report_path=tmp_path/'Results/Pruefung-own.html'
    page=report_path.read_text(encoding='utf-8')
    assert '<html lang="'+(locale or 'de')+'">' in page
    raw=json.loads(report_path.with_suffix('.json').read_text(encoding='utf-8'))
    assert raw['scope']==SCOPE and 'locale' not in raw
    assert raw['input']==plan['static_input'] and plan==before
    # Merely rendering another language never edits an already saved artifact.
    prior=report_path.read_bytes();render_static_report(raw,'en' if locale!='en' else 'de')
    assert report_path.read_bytes()==prior


def test_all_known_inspector_metadata_and_limitations_have_translations():
    from forensic_app.finding_summary import _DEFAULT_LIMITATION, _INSPECTORS
    translated=ReportText('en')
    for name,scope in _INSPECTORS.values():
        meta=translated.inspector({'name':name,'scope':scope,'status':'completed','limitations':[_DEFAULT_LIMITATION]})
        assert meta['name']!=name and meta['scope']!=scope
        assert meta['limitations'][0]!=_DEFAULT_LIMITATION
    assert translated.known_text(SCOPE,prefix='limitation.')!=SCOPE
    assert Path('forensic_app/locales/report.en.json').is_file()


def test_every_current_static_limitation_is_in_offline_catalog():
    import ast

    import forensic_app.static_analysis as static
    tree=ast.parse(Path(static.__file__).read_text(encoding='utf-8'))
    limitations=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Dict):
            for key,value in zip(node.keys,node.values,strict=True):
                if isinstance(key,ast.Constant) and key.value=='limitation' and isinstance(value,ast.Constant):
                    limitations.add(value.value)
        if (isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant)
                and any(isinstance(target,ast.Subscript) and isinstance(target.slice,ast.Constant) and target.slice.value=='limitation' for target in node.targets)):
            limitations.add(node.value.value)
        if isinstance(node,ast.keyword) and node.arg=='limitation' and isinstance(node.value,ast.Constant):
            limitations.add(node.value.value)
    known={value for key,value in catalog('de').items() if key.startswith('limitation.')}
    assert limitations and limitations<=known
