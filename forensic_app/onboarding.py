"""Offer bounded forensic tool-assignment guidance without installing or starting programs."""
from pathlib import Path

from forensic_app.interface_preferences import InterfacePreferences
from forensic_app.modes import ModeStore


def tool_guidance(storage):
    """Report missing assignments, records or program files in supported forensic drafts.

    Skip drafts with multiple tool blocks and bound returned requirements to 100.
    Presence checks are metadata only; this hint neither approves execution nor
    changes the saved dismissal preference.
    """
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
    return {'dismissed':InterfacePreferences(storage).get()['onboarding_dismissed'],
            'required':required[:100],'partial':len(required)>100,'skipped_unsupported':skipped,
            'scope':'supported_forensics'}
