"""Structured localization translates app errors, never canonical diagnostics or parameters."""
import json
import string

from fastapi.testclient import TestClient

from forensic_app.api import create_app
from forensic_app.app_errors import (
    AppValueError,
    ErrorText,
    catalog,
    error_detail,
    present_detail,
    request_locale,
)
from forensic_app.interface_preferences import InterfacePreferences
from forensic_app.storage import Storage


def test_error_catalog_parity_and_canonical_integrity():
    de,en=catalog('de'),catalog('en')
    assert de.keys()==en.keys()
    assert {"config.legacy_fields_warning", "config.legacy_confirmation_required"} <= de.keys()
    formatter=string.Formatter()
    for key,source in de.items():
        fields={field for _,field,_,_ in formatter.parse(source) if field is not None}
        assert fields=={field for _,field,_,_ in formatter.parse(en[key]) if field is not None}
        values={field:'<raw> C:\\Test\\Überprüfung.exe {not_a_template}' for field in fields}
        exc=AppValueError(key,**values)
        assert str(exc)==source.format_map(values)
        assert isinstance(exc,ValueError)
        token=request_locale.set('en')
        try:assert present_detail(error_detail(exc))==en[key].format_map(values)
        finally:request_locale.reset(token)
        assert str(exc)==source.format_map(values)
    assert error_detail(OSError('OS raw Überprüfung'))=='OS raw Überprüfung'


def test_request_language_auth_and_structured_wrappers(tmp_path):
    storage=Storage(tmp_path/'state')
    with TestClient(create_app(storage,'own-errors'),base_url='http://127.0.0.1') as client:
        assert client.get('/api/system').json()['detail']=='Zugriffstoken fehlt oder ist ungültig.'
        InterfacePreferences(storage).update(locale='en')
        response=client.get('/api/system')
        assert response.status_code==401
        assert response.json()['detail']=='Access token is missing or invalid.'
        assert response.json()['error_code'] in catalog('en')
        headers={'Authorization':'Bearer own-errors'}
        response=client.get('/api/jobs/00000000-0000-0000-0000-000000000000',headers=headers)
        assert response.status_code==404 and 'not found' in response.json()['detail'].lower()
        InterfacePreferences(storage).update(locale='de')
        assert client.get('/api/system').json()['detail']=='Zugriffstoken fehlt oder ist ungültig.'


def test_frozen_error_metadata_is_json_compatible():
    from forensic_app.job_errors import describe_error
    key=next(key for key,text in catalog('de').items() if text=='Ergebnisordner liegt außerhalb des Auftrags.')
    exc=AppValueError(key)
    detail=describe_error(exc,'Upload')
    restored=json.loads(json.dumps(detail))
    assert restored['error_code']==key and restored['error_params']=={}
    assert restored['type']=='ValueError' and restored['message']==str(exc)
    assert isinstance(ErrorText(key),str)
