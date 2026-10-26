"""Assemble a Windows release from an explicit EXE and repository documentation.

The offline wiki is shipped beside the executable, not loaded by the application.
Only the named release/project documents and docs/code-wiki tree are included; no data root,
evidence, tool binaries or session secrets are collected.
"""
import argparse
import hashlib
import re
import tomllib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from forensic_app import __version__


def main():
    """Validate matching versions, package the EXE/wiki and write the ZIP SHA256 sidecar.

    The caller supplies the already tested executable. This step does not build,
    start or reconfigure an application instance. The wiki entry point must exist.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    if version != __version__ or not re.fullmatch(r'\d+\.\d+\.\d+',version):
        raise ValueError('Versionsangaben stimmen nicht Ã¼berein.')
    wiki = root/'docs'/'code-wiki'
    if not (wiki/'index.html').is_file():
        raise ValueError('Offline code wiki entry point is missing.')
    documentation = [(path, 'docs/code-wiki/'+path.relative_to(wiki).as_posix())
                     for path in sorted(wiki.rglob('*')) if path.is_file()]
    # Keep relative README links usable in the fully extracted offline package.
    validation_name = 'VALIDATION_'+''.join(version.split('.')[:2])+'.md'
    for name in ('ARCHITECTURE.md', 'CONFIGURATION.md', validation_name,
                 'NEXT_TEST.md', 'releases/'+version+'.md'):
        documentation.append((root/'docs'/name, 'docs/'+name))
    args.output.mkdir(parents=True,exist_ok=True)
    archive = args.output/f'PostProcessingMagic-{version}-Windows.zip'
    with ZipFile(archive,'w',compression=ZIP_DEFLATED) as target:
        target.write(args.exe,'PostProcessingMagic.exe')
        target.write(root/'LICENSE','LICENSE')
        target.write(root/'README.md','README.md')
        target.writestr('EXE-SHA256.txt',hashlib.sha256(args.exe.read_bytes()).hexdigest()+'  PostProcessingMagic.exe\n')
        for path, name in documentation:
            target.write(path, name)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (args.output/f'PostProcessingMagic-{version}-Windows.sha256.txt').write_text(digest+'  '+archive.name+'\n',encoding='utf-8')
    with ZipFile(archive) as target:
        assert target.testzip() is None
        assert target.namelist() == ['PostProcessingMagic.exe','LICENSE','README.md','EXE-SHA256.txt'] + [name for _, name in documentation]
    print(archive)
    print(digest)


if __name__ == '__main__':
    main()
