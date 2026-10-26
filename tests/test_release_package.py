import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile

from forensic_app import __version__
from tools.package_release import main


def test_new_package_contains_readme_and_only_explicit_release_files(tmp_path,monkeypatch):
    exe=tmp_path/'own.exe';exe.write_bytes(b'Synthetic fixture, never executed')
    output=tmp_path/'release'
    monkeypatch.setattr(sys,'argv',['package_release','--exe',str(exe),'--output',str(output)])
    main()
    archive=next(output.glob('*.zip'))
    with ZipFile(archive) as z:
        wiki = Path(__file__).resolve().parents[1]/'docs'/'code-wiki'
        docs = [(path, 'docs/code-wiki/'+path.relative_to(wiki).as_posix())
                for path in sorted(wiki.rglob('*')) if path.is_file()]
        validation_name = 'VALIDATION_'+''.join(__version__.split('.')[:2])+'.md'
        for name in ('ARCHITECTURE.md', 'CONFIGURATION.md', validation_name,
                     'NEXT_TEST.md', 'releases/'+__version__+'.md'):
            docs.append((wiki.parent/name, 'docs/'+name))
        assert docs and any(name == 'docs/code-wiki/index.html' for _, name in docs)
        assert z.namelist() == ['PostProcessingMagic.exe','LICENSE','README.md','EXE-SHA256.txt'] + [name for _, name in docs]
        for path, name in docs:
            assert z.read(name) == path.read_bytes(), name
        assert z.read('README.md').startswith(b'# Post-Processing-Magic')
        assert hashlib.sha256(exe.read_bytes()).hexdigest() in z.read('EXE-SHA256.txt').decode()
    assert hashlib.sha256(archive.read_bytes()).hexdigest() in next(output.glob('*.sha256.txt')).read_text()
