"""Synthetic preferences/onboarding: no real tools, data or GUI starts."""
import sqlite3

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from forensic_app.api import create_app
from forensic_app.interface_preferences import InterfacePreferences
from forensic_app.storage import Storage


def test_preferences_defaults_atomic_patch_and_restart(tmp_path):
    storage=Storage(tmp_path/'state')
    prefs=InterfacePreferences(storage)
    assert prefs.get()=={'locale':'de','onboarding_dismissed':False}
    assert not storage.database.exists()
    prefs.update(locale='en')
    prefs.update(onboarding_dismissed=True)
    assert InterfacePreferences(storage).get()=={'locale':'en','onboarding_dismissed':True}
    for patch in ({'locale':'fr'},{'onboarding_dismissed':'yes'},{'onboarding_dismissed':1}):
        with pytest.raises(ValidationError):prefs.update(**patch)
    assert prefs.get()['locale']=='en'


def test_onboarding_auth_assignment_program_and_persistent_dismissal(tmp_path):
    storage=Storage(tmp_path/'state')
    headers={'Authorization':'Bearer own-interface'}
    with TestClient(create_app(storage,'own-interface'),base_url='http://127.0.0.1',headers=headers) as client:
        original=client.get('/api/settings/configuration/export').json()
        for url in ['/api/settings/interface','/api/settings/onboarding']:
            assert client.get(url,headers={'Authorization':''}).status_code==401
        hint=client.get('/api/settings/onboarding').json()
        assert not hint['dismissed'] and hint['required'][0]['status']=='missing_assignment'
        assert [item['name'] for item in hint['optional']]==['Timeline Explorer','EZViewer']
        assert client.put('/api/settings/interface',json={'locale':'en'}).status_code==200
        assert client.put('/api/settings/interface',json={'locale':'../de'}).status_code==422
        assert client.put('/api/settings/interface',json={'onboarding_dismissed':True}).status_code==200
        assert client.get('/api/settings/onboarding').json()['dismissed']
        after=client.get('/api/settings/configuration/export').json()
        for key in ['tools','modes','malware_modes','limits']:assert after[key]==original[key]
        with sqlite3.connect(storage.database) as c:assert c.execute('SELECT count(*) FROM jobs').fetchone()[0]==0
    assert InterfacePreferences(storage).get()=={'locale':'en','onboarding_dismissed':True}
