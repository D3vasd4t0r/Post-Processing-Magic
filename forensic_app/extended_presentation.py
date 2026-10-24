"""Read-only, escaped report sections for bounded captured evidence metadata."""
import html


def render_extended(report, t, section, table):
    parts=[]
    def text(key):
        return t('extended.'+key)
    def status(value):
        return t('status.'+value) if isinstance(value,str) and 'status.'+value in t.de else value
    def notice(value):
        return '<p>'+html.escape(str(value))+'</p>'
    for detail in report.get('pe_details',[])[:8]:
        imported=detail.get('imports',{})
        rows=[]
        for library in imported.get('entries',[])[:256]:
            for function in library.get('functions',[]):
                if len(rows)>=500:break
                rows.append((library.get('dll'),function.get('name') if function.get('kind')=='name' else '#'+str(function.get('ordinal')),
                             library.get('thunk_source')))
            if len(rows)>=500:break
        import_status=status(imported.get('status','unknown'))
        parts.append(section(text('imports'),notice(text('imports_scope'))+notice(import_status)+
                             notice(', '.join(imported.get('reasons',[])))+
                             table([text('library'),text('function'),text('source')],rows)+notice(text('display_limit'))))
        resources=detail.get('resources',{})
        resource_rows=[('/'.join(str(p.get('name',p.get('id',''))) for p in item.get('path',[])),
                        item.get('file_offset'),item.get('bytes'),item.get('data_range_valid'))
                       for item in resources.get('entries',[])[:200]]
        parts.append(section(text('resources'),notice(text('resources_scope'))+notice(status(resources.get('status')))+
                             notice(', '.join(resources.get('reasons',[])))+
                             table([text('path'),text('offset'),text('bytes'),text('range')],resource_rows)+notice(text('display_limit'))))
        overlay=detail.get('overlay',{})
        parts.append(section(text('overlay'),notice(text('overlay_scope'))+notice(status(overlay.get('status')))+
                             notice(', '.join(overlay.get('reasons',[])))+
                             table([text('offset'),text('bytes')],[(r.get('file_offset'),r.get('bytes')) for r in overlay.get('entries',[])[:256]])+
                             table([text('certificates'),text('overlay_bytes')],[(len(overlay.get('certificate_entries',[])),overlay.get('overlay_bytes'))])))
    if report.get('pe_details_partial'):
        parts.append(section(text('pe_details'),notice(text('snapshot_limit'))))
    indicators=report.get('indicators')
    if isinstance(indicators,dict):
        rows=[]
        for item in indicators.get('indicators',[])[:200]:
            sources='; '.join(str(source.get('source_step',''))+' @ '+str(source.get('byte_offset'))
                              for source in item.get('sources',[])[:8])
            rows.append((item.get('type'),item.get('value'),sources))
        parts.append(section(text('indicators'),notice(text('indicators_scope'))+
                             notice(status(indicators.get('status')))+notice(', '.join(indicators.get('reasons',[])))+
                             table([text('type'),text('value'),text('source_offset')],rows)+notice(text('indicator_display_limit'))))
    for command in report.get('configuration',{}).get('commands',[]):
        manifest=command.get('module_manifest')
        if not isinstance(manifest,dict):continue
        rows=[(item.get('relative_path'),item.get('category'),item.get('size'),item.get('sha256'))
              for item in manifest.get('files',[])[:256]]
        unknown=[(item.get('selection'),item.get('reason')) for item in manifest.get('unresolved',[])[:256]]
        parts.append(section(text('module_manifest'),notice(text('module_scope'))+
                             table([text('path'),text('type'),text('bytes'),'SHA-256'],rows)+
                             table([text('unresolved'),text('reason')],unknown)))
    return parts
