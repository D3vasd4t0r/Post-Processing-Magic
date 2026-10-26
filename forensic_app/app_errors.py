"""Structured application errors; canonical diagnostics are never translated."""
import json
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path

request_locale = ContextVar('request_locale', default='de')

@lru_cache(maxsize=2)
def catalog(locale):
    """Cache a bundled structured-error catalog, defaulting unsupported locales to German."""
    language = locale if locale in ('de', 'en') else 'de'
    return json.loads((Path(__file__).parent/'locales'/f'errors.{language}.json').read_text(encoding='utf-8'))

class ErrorText(str):
    """Carry an app error code and parameters while retaining canonical German string content.

    Localization is a presentation operation; constructing the value does not use
    request locale, so persisted diagnostics can retain their canonical wording."""
    def __new__(cls, code, **params):
        """Create canonical string content and retain code/parameters for later localized rendering."""
        instance = super().__new__(cls, catalog('de')[code].format_map(params))
        instance.code, instance.params = code, params
        return instance

    def localized(self, locale=None):
        """Render the chosen/request locale, recursively localizing only nested ErrorText parameters."""
        language = locale or request_locale.get()
        params = {key: value.localized(language) if isinstance(value, ErrorText) else value for key, value in self.params.items()}
        return catalog(language).get(self.code, catalog('de')[self.code]).format_map(params)

class AppValueError(ValueError):
    """Expose a structured ErrorText through ValueError without changing its canonical message."""
    def __init__(self, code, **params):
        self.text = ErrorText(code, **params)
        super().__init__(str(self.text))

def error_detail(exc):
    """Keep structured app messages through HTTP wrappers; unknown OS errors stay raw."""
    return exc.text if isinstance(exc, AppValueError) else str(exc)

def present_detail(value):
    """Project structured error values recursively for HTTP presentation, leaving other data intact."""
    if isinstance(value, ErrorText):
        return value.localized()
    if isinstance(value, dict):
        return {key: present_detail(item) for key, item in value.items()}
    if isinstance(value, list):
        return [present_detail(item) for item in value]
    return value
