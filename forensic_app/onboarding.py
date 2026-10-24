"""Configuration guidance only: no installation, program start, or profile approval."""
from pathlib import Path

from forensic_app.interface_preferences import InterfacePreferences
from forensic_app.modes import ModeStore


def tool_guidance(storage):
    tools={tool['id']:tool for tool in storage.list_tools()}
    required=[]
    skipped=0
    for mode in ModeStore(storage).list_modes():
        blocks=[step for step in mode.get('steps',[]) if step.get('type','tool')=='tool']
        if len(blocks)>1:
            skipped+=1
            continue
        for step in blocks:
            tool=tools.get(step.get('tool_id'))
            status=None
            if not step.get('tool_id'):
                status='missing_assignment'
            elif tool is None:
                status='missing_tool'
            else:
                try:
                    if not Path(tool['path']).is_file():
                        status='missing_program'
                except OSError:
                    status='missing_program'
            if status:
                required.append({'mode_name':mode['name'],'step_name':step['name'],
                                 'tool_name':tool['name'] if tool else step.get('tool_hint',''),
                                 'status':status})
    names={tool['name'].casefold() for tool in tools.values()}
    return {'dismissed':InterfacePreferences(storage).get()['onboarding_dismissed'],
            'required':required[:100],'partial':len(required)>100,'skipped_unsupported':skipped,
            'optional':[{'name':name,'configured':name.casefold() in names}
                        for name in ['Timeline Explorer','EZViewer']],
            'scope':'supported_forensics_and_optional_result_viewers'}
