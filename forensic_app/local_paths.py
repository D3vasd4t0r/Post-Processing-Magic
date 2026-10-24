
from pathlib import Path

from forensic_app.app_errors import AppValueError


def validate_local_path(value: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise AppValueError('error.92ba731cf2d1')
    if value.startswith(("\\\\", "//")):
        raise AppValueError('error.2e1159f8770f')
    if not Path(value).is_absolute():
        raise AppValueError('error.d57bd3a524e2')
    return value
