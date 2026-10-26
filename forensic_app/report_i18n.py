"""Offline report presentation, independent of mutable interface preferences.

Only callers' explicit application metadata fields use known_text; arbitrary data
and raw JSON must never be passed through a translation/replacement operation.
"""
import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=2)
def catalog(locale):
    """Cache bundled report messages independently of mutable interface preferences."""
    language = locale if locale in ('de', 'en') else 'de'
    return json.loads((Path(__file__).parent/'locales'/f'report.{language}.json').read_text(encoding='utf-8'))


class ReportText:
    """Render report labels using the frozen report locale and German fallback."""
    def __init__(self, locale='de'):
        self.locale = locale if locale in ('de', 'en') else 'de'
        self.de = catalog('de')
        self.messages = catalog(self.locale)

    def __call__(self, key, **params):
        """Format a report label with locale, German and key fallbacks, preserving supplied values."""
        return self.messages.get(key, self.de.get(key, key)).format_map(params)

    def known_text(self, value, *, prefix):
        """Translate exact known app metadata only, retaining unknown historical text."""
        for key, original in self.de.items():
            if key.startswith(prefix) and value == original:
                return self(key)
        return value

    def value(self, value):
        """Translate only None and actual bool values; retain arbitrary metadata unchanged."""
        if value is None:
            return self('unknown')
        if type(value) is bool:
            return self('true' if value else 'false')
        return value
