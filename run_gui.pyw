"""Double-click launcher for the desktop window (Windows opens .pyw files without a console).

Uses config.yaml next to this file. Equivalent to:  python -m snmp2opcua.gui -c config.yaml
"""
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
os.chdir(here)
sys.path.insert(0, here)

from snmp2opcua.gui import main  # noqa: E402

sys.exit(main(["-c", os.path.join(here, "config.yaml")] + sys.argv[1:]))
