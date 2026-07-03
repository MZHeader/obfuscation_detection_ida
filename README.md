# Obfuscation Detection for IDA Pro

> Port of [mrphrazer/obfuscation_detection](https://github.com/mrphrazer/obfuscation_detection)
> by [Tim Blazytko](https://github.com/mrphrazer).

Same idea as the original but for IDA Pro. Flagged functions get a
repeatable comment saying why they were flagged. Findings tied to a specific instruction also get a comment on that line. Results also show up in a dockable table and get logged to the Output window.

## What it looks for

Heuristics:

* State machines / control-flow flattening
* High cyclomatic complexity
* Unusually large basic blocks
* Overlapping instructions (bytes disassembled two different ways)
* Rare 3-gram opcode sequences vs reference tables for x86, x86_64, ARM, AArch64
* Popular helpers (things called from lots of places, common for string decrypt)
* Functions with many natural loops
* Irreducible loops
* XOR-by-constant inside a loop
* Mixed boolean-arithmetic (needs Hex-Rays; excluded from `run_all` since it can crash IDA on some binaries)
* Repeated CFG subgraphs
* Basic-block-splitting (high blocks-per-branch ratio)

Utilities:

* Entry / leaf / recursive functions
* Section entropy
* RC4 KSA and PRGA candidates

## Install

Drop `obfuscation_detection.py` and `obfuscation_detection_ida/` into your IDA plugins directory.

### Linux / macOS

```
~/.idapro/plugins/obfuscation_detection.py
~/.idapro/plugins/obfuscation_detection_ida/
```

### Windows

```
%APPDATA%\Hex-Rays\IDA Pro\plugins\obfuscation_detection.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\obfuscation_detection_ida\
```

Restart IDA. You should see `[obfdet] Obfuscation Detection 1.0 loaded.` in
the Output window.

## Usage 
The plugin adds an entry under
**Edit > Plugins > Obfuscation Detection** that opens a menu with every
heuristic.

![Chooser dialog](imgs/chooser.png)

Open **Show Results View** once at the start of a session to get a dockable table that accumulates findings as you go. One row per function, sorted by how many heuristics fired. Double-clicking a row jumps to that function.

![Results view](imgs/results.png)

From the IDAPython console:

```python
from obfuscation_detection_ida import (
    run_all,
    run_heuristics,
    run_utils,
    find_state_machines,
    find_xor_decryption_loops,
)

run_all()
```

Findings are added as a comment: `[obfdet] Heuristic: State Machine: ...`. 

## Notes about the port

A few things differ from the Binary Ninja original because IDA's SDK
doesn't give you the same primitives:

* No first-class tag types in IDA. Findings are added as a comment, prefixed with `[obfdet]`.
* Dominators, dominance frontiers, and back-edge detection are computed
  by the plugin (Cooper-Harvey-Kennedy). IDA's `FlowChart` doesn't hand
  those to you.
* XOR-in-loop and RC4 PRGA detection run on assembly mnemonics rather than
  a lifted IL, since IDA has no LLIL equivalent that's usable without the
  decompiler. Common `xor`/`eor` patterns are caught. XOR expressed via
  lifted arithmetic is not.
* Mixed-boolean-arithmetic detection uses Hex-Rays microcode at
  `MMAT_LVARS`. If the decompiler isn't installed the heuristic returns 0
  for every function rather than blowing up. Absolute counts aren't
  comparable to the Binary Ninja HLIL-based scores, but the ranking is.
* The uncommon-instruction-sequence heuristic only runs on x86, x86_64,
  ARM, and AArch64. Other architectures are skipped with a message
  instead of falling through to the LLIL n-gram database (which we can't
  compute in IDA).
* Results view is a Qt dock; PySide6 / PySide2 / PyQt5 are tried in that
  order. Without any of them the plugin still tags functions and prints
  to the Output window.

## Credit

All the actual research and heuristics come from Tim Blazytko's original
[obfuscation_detection](https://github.com/mrphrazer/obfuscation_detection).
