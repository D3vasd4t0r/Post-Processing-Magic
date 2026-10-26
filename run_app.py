"""Frozen executable entry point shared by controller, server and worker modes.

freeze_support handles multiprocessing bootstrap before the launcher dispatches
normal CLI modes. The main guard prevents startup during module imports.
"""

from multiprocessing import freeze_support

from forensic_app.launcher import main

if __name__ == "__main__":
    freeze_support()
    raise SystemExit(main())

