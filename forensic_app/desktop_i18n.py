"""Offline desktop catalogs. Translate app labels, never user or exception text."""
import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=2)
def catalog(locale='de'):
    locale = locale if locale in ('de','en') else 'de'
    return json.loads((Path(__file__).parent/'locales'/f'desktop.{locale}.json').read_text(encoding='utf-8'))


class DesktopTranslations:
    def __init__(self,locale='de'):
        self.locale = locale if locale in ('de','en') else 'de'

    def t(self,key,**parameters):
        template = catalog(self.locale).get(key,catalog('de').get(key,key))
        return template.format_map(parameters)


class DesktopError(RuntimeError):
    """App-owned failure with an untranslated original detail parameter."""
    def __init__(self,key,**parameters):
        self.key,self.parameters = key,parameters
        super().__init__(DesktopTranslations().t(key,**parameters))

    def translated(self,translate):
        return translate(self.key,**self.parameters)
