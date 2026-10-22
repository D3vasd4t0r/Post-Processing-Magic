from pathlib import Path


def validate_local_path(value: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Steuerzeichen sind nicht erlaubt.")
    if value.startswith(("\\\\", "//")):
        raise ValueError("Bitte einen lokalen Pfad auf dem Server verwenden, keinen UNC-Pfad.")
    if not Path(value).is_absolute():
        raise ValueError("Bitte einen absoluten Pfad auf dem Server ohne Anführungszeichen angeben.")
    return value
