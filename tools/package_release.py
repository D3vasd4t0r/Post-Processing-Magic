"""Create the distributable from an explicit executable; no runtime directories."""
import argparse
import hashlib
import re
import tomllib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from forensic_app import __version__


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    if version != __version__ or not re.fullmatch(r'\d+\.\d+\.\d+',version):
        raise ValueError('Versionsangaben stimmen nicht überein.')
    args.output.mkdir(parents=True,exist_ok=True)
    archive = args.output/f'PostProcessingMagic-{version}-Windows.zip'
    with ZipFile(archive,'w',compression=ZIP_DEFLATED) as target:
        target.write(args.exe,'PostProcessingMagic.exe')
        target.write(root/'LICENSE','LICENSE')
        target.write(root/'README.md','README.md')
        target.writestr('EXE-SHA256.txt',hashlib.sha256(args.exe.read_bytes()).hexdigest()+'  PostProcessingMagic.exe\n')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (args.output/f'PostProcessingMagic-{version}-Windows.sha256.txt').write_text(digest+'  '+archive.name+'\n',encoding='utf-8')
    with ZipFile(archive) as target:
        assert target.testzip() is None
        assert target.namelist() == ['PostProcessingMagic.exe','LICENSE','README.md','EXE-SHA256.txt']
    print(archive)
    print(digest)


if __name__ == '__main__':
    main()
