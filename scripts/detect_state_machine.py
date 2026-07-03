"""Headless: only state-machine detection.

Invoke with:
    idat -A -Sscripts/detect_state_machine.py <binary>
"""

import os
import sys

import ida_auto
import ida_pro

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

ida_auto.auto_wait()

from obfuscation_detection_ida import find_state_machines

find_state_machines()
ida_pro.qexit(0)
