"""Headless entry point.

Invoke with:
    idat -A -Sscripts/detect_obfuscation.py <binary>

The script waits for auto-analysis to finish, runs every heuristic, then
exits, leaving an IDB with tagged functions behind.
"""

import os
import sys

import ida_auto
import ida_pro

# Locate the sibling package regardless of where IDA was launched from.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

ida_auto.auto_wait()

from obfuscation_detection_ida import run_all

run_all()

ida_pro.qexit(0)
