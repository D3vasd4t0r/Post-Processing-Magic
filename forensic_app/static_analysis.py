"""Bounded read-only byte inspection. No sample loading, extraction or subprocess calls."""
import hashlib
import html
import json
import math
import re
import struct
from collections import Counter
from pathlib import Path, PureWindowsPath

from forensic_app.malware_modes import MAX_SAMPLE_BYTES
from forensic_app.windows_access import input_identity, locked_input
from forensic_app.zip_safety import ensure_space

EXTENSIONS = {'PDF':{'.pdf'},'EXE':{'.exe','.dll','.sys','.scr'},
              'OFFICE':{'.doc','.docx','.docm','.xls','.xlsx','.xlsm','.ppt','.pptx','.pptm'}}
SCOPE = ('Nur statische Rohdatenprüfung. Keine Ausführung, kein Rendering, keine Makros, '
         'kein Internetzugriff. Indikatoren sind keine Malware-Diagnose und keine Entwarnung.')


def validate_name(name,kind):
    if Path(name.replace('\\','/')).suffix.casefold() not in EXTENSIONS[kind]:
        raise ValueError('Dateiendung passt nicht zum gewählten Malware-Modul. Einzeldatei PDF, Office oder PE wählen; kein ZIP-Eingang.')


def identify(source,kind):
    source.seek(0)
    head = source.read(4096)
    if kind == 'PDF' and b'%PDF-' in head[:1024]:
        return 'PDF-Signatur (kein Nachweis eines vollständigen PDF-Dokuments)'
    if kind == 'OFFICE' and head.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
        return 'OLE Compound File (Legacy Office; Inhalte nicht geparst)'
    if kind == 'OFFICE' and head.startswith(b'PK\x03\x04'):
        return 'ZIP-basierter Office-Kandidat (Containerprüfung folgt im Office-Block)'
    if kind == 'EXE' and head.startswith(b'MZ') and len(head)>=64:
        offset = struct.unpack_from('<I',head,60)[0]
        if 64 <= offset <= min(MAX_SAMPLE_BYTES-24,16*1024**2):
            source.seek(offset)
            if source.read(4) == b'PE\0\0':
                return 'Windows Portable Executable (PE)'
    raise ValueError('Dateisignatur passt nicht zum gewählten Format oder Header ist beschädigt. Datei wird nicht ausgeführt.')


def prepare_sample(store,ident,plan,work,check):
    """Freeze local/upload bytes under a neutral name, never open via Windows shell."""
    root = store.paths(ident)[0]
    path = Path(plan['local_input']['path']) if plan['source_kind']=='local' else root/'evidence'/ident/'Evidence.bin'
    folder = work/'Sample'
    folder.mkdir()
    destination = folder/'input.bin'
    state = store.get(ident)
    with locked_input(path) as source:
        identity = input_identity(source)
        if not 0 < identity['size'] <= MAX_SAMPLE_BYTES:
            raise ValueError('Statische Erstversion: Einzeldateien von 1 Byte bis 256 MiB.')
        if plan['source_kind']=='local' and identity != {k:plan['local_input'][k] for k in identity}:
            raise ValueError('Lokale Eingangsdatei wurde seit der Auswahl verändert.')
        signature = identify(source,plan['mode']['evidence_format'])
        source.seek(0)
        sha1,sha256 = hashlib.sha1(),hashlib.sha256()
        copied = 0
        with destination.open('xb') as target:
            while chunk := source.read(1024**2):
                check()
                copied += len(chunk)
                if copied > MAX_SAMPLE_BYTES:
                    raise ValueError('Samplelimit überschritten.')
                ensure_space(work,len(chunk))
                target.write(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        if copied != identity['size'] or (state['input_sha256'] and state['input_sha256'] != sha256.hexdigest()):
            raise ValueError('Eingangsdatei hat sich verändert oder ist unvollständig.')
    store.update(ident,input_sha1=sha1.hexdigest(),input_sha256=sha256.hexdigest(),input_size=copied)
    return {'signature':signature,'bytes':copied,'sha1':sha1.hexdigest(),'sha256':sha256.hexdigest()}


def office_directory(source,size,check):
    source.seek(0)
    if source.read(8).startswith(b'\xd0\xcf\x11\xe0'):
        return {'container':'OLE','limitation':'Legacy-OLE-Inhalte werden in 0.25 nicht geparst; oleid-Adapter folgt. Keine Aussage zu Makros.'}
    source.seek(max(0,size-65557))
    tail = source.read(65557)
    index = tail.rfind(b'PK\x05\x06')
    if index < 0 or index+22 > len(tail):
        raise ValueError('Office-ZIP-Endverzeichnis fehlt oder ist beschädigt.')
    disk,start_disk,disk_count,count,length,offset,comment = struct.unpack_from('<4H2IH',tail,index+4)
    if disk or start_disk or disk_count!=count or count>10000 or length>4*1024**2 or offset+length>size or index+22+comment!=len(tail):
        raise ValueError('Office-Containergrenzen verletzt oder ZIP64/mehrteiliges Archiv nicht unterstützt.')
    source.seek(offset)
    data = source.read(length)
    entries,position = [],0
    for entry_index in range(count):
        if entry_index%64==0:
            check()
        if position+46>len(data) or data[position:position+4]!=b'PK\x01\x02':
            raise ValueError('Office-Zentralverzeichnis beschädigt.')
        flags = struct.unpack_from('<H',data,position+8)[0]
        compressed,expanded = struct.unpack_from('<II',data,position+20)
        n,e,c = struct.unpack_from('<HHH',data,position+28)
        end = position+46+n+e+c
        if n>2048 or end>len(data):
            raise ValueError('Office-Verzeichniseintrag überschreitet Grenzen.')
        name = data[position+46:position+46+n].decode('utf-8' if flags&2048 else 'cp437',errors='replace')
        entries.append({'name':name,'compressed_bytes':compressed,'declared_bytes':expanded,'encrypted':bool(flags&1)})
        position = end
    if position!=len(data):
        raise ValueError('Unerwartete Daten im Office-Zentralverzeichnis.')
    names = [e['name'].replace('\\','/').casefold() for e in entries]
    if '[content_types].xml' not in names or not any(n.startswith(('word/','xl/','ppt/')) for n in names):
        raise ValueError('ZIP enthält keine erkennbare Office-Open-XML-Verzeichnisstruktur.')
    return {'container':'OOXML','entries':entries,'macro_named_entries':[e['name'] for e in entries if 'vbaproject' in e['name'].casefold()],
            'embedded_named_entries':[e['name'] for e in entries if '/embeddings/' in e['name'].casefold()],
            'limitation':'Nur Verzeichnisnamen und deklarierte Größen; keine Entpackung, XML-, Makro- oder Beziehungsanalyse. Namen sind unbestätigte Metadaten.'}


def pe_headers(source,size):
    source.seek(60)
    offset = struct.unpack('<I',source.read(4))[0]
    source.seek(offset)
    data = source.read(24)
    if len(data)!=24 or data[:4]!=b'PE\0\0':
        raise ValueError('PE-Header beschädigt.')
    machine,count,timestamp,_ptr,_symbols,optional,characteristics = struct.unpack_from('<HHIIIHH',data,4)
    if not 0<count<=96 or optional>4096 or offset+24+optional+count*40>size:
        raise ValueError('PE-Sektionstabelle liegt außerhalb der Datei oder überschreitet das Limit.')
    source.seek(offset+24+optional)
    sections=[]
    for _ in range(count):
        entry=source.read(40)
        virtual_size,address,raw_size,raw_offset=struct.unpack_from('<IIII',entry,8)
        sections.append({'name':entry[:8].rstrip(b'\0').decode('ascii',errors='replace'),'virtual_bytes':virtual_size,
                         'virtual_address':address,'raw_bytes':raw_size,'raw_offset':raw_offset,
                         'raw_range_valid':raw_offset+raw_size<=size})
    return {'machine_hex':hex(machine),'coff_timestamp_untrusted':timestamp,'characteristics_hex':hex(characteristics),
            'sections':sections,'limitation':'Kein Laden von DLLs, keine Imports-Auflösung, Signaturvalidierung oder Disassemblierung. Zeitstempel kann manipuliert sein.'}


def inspect_sample(kind,path,format,check):
    with locked_input(path) as source:
        size = input_identity(source)['size']
        identify(source,format)
        if kind=='office':
            return office_directory(source,size,check)
        if kind=='pe':
            return pe_headers(source,size)
        source.seek(0)
        chunks=[]
        budget = 16*1024**2 if kind=='pdf' else 8*1024**2 if kind=='strings' else 1024**2
        remaining=min(size,budget)
        while remaining:
            check()
            chunk=source.read(min(remaining,1024**2))
            if not chunk:
                break
            chunks.append(chunk)
            remaining-=len(chunk)
        data=b''.join(chunks)
        result={'inspected_bytes':len(data),'file_bytes':size,'partial':size>len(data)}
        if kind=='metadata':
            counts=Counter(data)
            result['entropy_bits_per_byte']=round(-sum((n/len(data))*math.log2(n/len(data)) for n in counts.values()),4) if data else 0
            result['limitation']='Entropie nur über das erste MiB; hohe Entropie allein ist kein Malware-Nachweis.'
        elif kind=='strings':
            strings=[]
            for encoding,pattern in [('ascii',rb'[\x20-\x7e]{6,256}'),('utf-16le',rb'(?:[\x20-\x7e]\x00){6,256}')]:
                for match in re.finditer(pattern,data):
                    check()
                    strings.append({'offset':match.start(),'encoding':encoding,'text':match.group().decode(encoding)})
                    if len(strings)>=2000:
                        break
                if len(strings)>=2000:
                    break
            result.update(strings=strings,entry_limit=2000,string_length_limit=256,
                          limit_reached=len(strings)>=2000,limitation='Rohtext nur aus den ersten 8 MiB, keine URLs öffnen oder Inhalte ausführen.')
        elif kind=='pdf':
            # Decode PDF name escapes only in names; no objects, streams or scripts evaluated.
            counts=Counter()
            keywords={'JavaScript','JS','OpenAction','AA','Launch','EmbeddedFile','RichMedia','Encrypt','ObjStm','XFA'}
            token_count=0
            for match in re.finditer(rb'/[A-Za-z0-9#]{1,128}',data):
                if token_count%256==0:
                    check()
                if token_count>=100000:
                    break
                token_count+=1
                name=re.sub(rb'#([0-9A-Fa-f]{2})',lambda m:bytes([int(m[1],16)]),match.group()[1:]).decode('ascii',errors='replace')
                if name in keywords:
                    counts[name]+=1
            result.update(keyword_counts={k:counts[k] for k in sorted(keywords)},name_token_limit=100000,
                          name_token_limit_reached=token_count>=100000,
                          limitation='Wörtliche Namen, auch Kommentare/Strings können zählen. Komprimierte/verschlüsselte Inhalte nicht ausgewertet. Kein PDFID-Ersatz, keine Malware-Bewertung.')
        else:
            raise ValueError('Unbekannte interne statische Prüfung.')
        return result


def run_static(plan,work,check,emit):
    kind=plan['inspector']
    check()
    result={'scope':SCOPE,'inspection':kind,'input':plan['static_input'],
            'findings':inspect_sample(kind,work/'Sample/input.bin',plan['mode']['evidence_format'],check)}
    output=work/Path(*PureWindowsPath(plan['mode']['output_folder']).parts)
    output.mkdir(parents=True,exist_ok=True)
    name='Pruefung-'+plan['id']
    encoded=json.dumps(result,ensure_ascii=False,indent=2)
    ensure_space(output,len(encoded.encode('utf-8'))*3)
    (output/(name+'.json')).write_text(encoded,encoding='utf-8')
    rendered='<!doctype html><html lang="de"><meta charset="utf-8"><title>Statische Prüfung</title><style>body{background:#1b0e14;color:#f4dce2;font:16px/1.5 system-ui;padding:30px;max-width:1100px;margin:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#2c1720;padding:24px;border:1px solid #9b4157;border-radius:12px}h1{color:#ff8fa9}</style><h1>Statische Prüfung: '+html.escape(kind)+'</h1><p>'+html.escape(SCOPE)+'</p><pre>'+html.escape(encoded)+'</pre></html>'
    (output/(name+'.html')).write_text(rendered,encoding='utf-8')
    emit('Statische Prüfung abgeschlossen: '+kind+'; Ergebnisdateien gespeichert. Keine Datei ausgeführt.\n')
    return 0
