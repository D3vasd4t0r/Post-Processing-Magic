"""Module entry point with multiprocessing bootstrap guarded for frozen workers."""
from multiprocessing import freeze_support

from forensic_app.launcher import main

if __name__ == "__main__":
    freeze_support()
    raise SystemExit(main())

