import hashlib
import sys
from zipfile import ZipFile

from tools.package_release import main


def test_new_package_contains_readme_and_only_explicit_release_files(tmp_path,monkeypatch):
    exe=tmp_path/'own.exe';exe.write_bytes(b'Synthetic fixture, never executed')
    output=tmp_path/'release'
    monkeypatch.setattr(sys,'argv',['package_release','--exe',str(exe),'--output',str(output)])
    main()
    archive=next(output.glob('*.zip'))
    with ZipFile(archive) as z:
        assert z.namelist()==['PostProcessingMagic.exe','LICENSE','README.md','EXE-SHA256.txt']
        assert z.read('README.md').startswith(b'# Post-Processing-Magic')
        assert hashlib.sha256(exe.read_bytes()).hexdigest() in z.read('EXE-SHA256.txt').decode()
    assert hashlib.sha256(archive.read_bytes()).hexdigest() in next(output.glob('*.sha256.txt')).read_text()
