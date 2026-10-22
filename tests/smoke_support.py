"""Bounded startup wait with actionable, token-free synthetic-test diagnostics."""
import time


def wait_ready(session,timeout=60):
    end=time.monotonic()+timeout
    last={}
    while time.monotonic()<end:
        last=session.poll()
        if last['ready']:
            return last
        if not last['alive']:
            break
        time.sleep(.15)
    # Never print the full poll dictionary: it contains the session token.
    raise RuntimeError('Own EXE startup failed. '+str(last.get('problem',''))+
                       '\nStartup log:\n'+session.startup_log()[-3000:])
