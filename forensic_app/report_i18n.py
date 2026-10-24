"""Offline report presentation, independent of mutable interface preferences.

Only callers' explicit application metadata fields use known_text; arbitrary data
and raw JSON must never be passed through a translation/replacement operation.
"""
import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=2)
def catalog(locale):
    language = locale if locale in ('de', 'en') else 'de'
    return json.loads((Path(__file__).parent/'locales'/f'report.{language}.json').read_text(encoding='utf-8'))


class ReportText:
    def __init__(self, locale='de'):
        self.locale = locale if locale in ('de', 'en') else 'de'
        self.de = catalog('de')
        self.messages = catalog(self.locale)

    def __call__(self, key, **params):
        return self.messages.get(key, self.de.get(key, key)).format_map(params)

    def known_text(self, value, *, prefix):
        """Translate exact known app metadata only, retaining unknown historical text."""
        for key, original in self.de.items():
            if key.startswith(prefix) and value == original:
                return self(key)
        return value

    def value(self, value):
        if value is None:
            return self('unknown')
        if type(value) is bool:
            return self('true' if value else 'false')
        return value

    def inspector(self, inspector):
        """Return a localized copy; source summary/JSON remains untouched."""
        return dict(inspector,
                    name=self.known_text(inspector['name'], prefix='inspector.'),
                    scope=self.known_text(self.known_text(inspector['scope'], prefix='inspector.'), prefix='office.'),
                    status=self('status.'+inspector['status']) if 'status.'+inspector['status'] in self.de else inspector['status'],
                    limitations=[self.known_text(v, prefix='limitation.') for v in inspector['limitations']])


    def coverage(self, summary):
        """Show a limit only for the inspector that actually applies it."""
        inspector_id=summary['inspector'].get('id')
        rows=[]
        for key,value in summary['coverage'].items():
            if key=='entry_limit_reached' and inspector_id!='strings':
                continue
            if key=='name_token_limit_reached' and inspector_id!='pdf':
                continue
            label=self('coverage.'+key) if 'coverage.'+key in self.de else key
            rows.append((label,self.value(value)))
        return rows
