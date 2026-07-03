# Obfuscation Detection for IDA Pro

Port of Tim Blazytko's [obfuscation_detection](https://github.com/mrphrazer/obfuscation_detection)
plugin (originally for Binary Ninja) to IDA Pro. A Ghidra version also lives
at [mrphrazer/obfuscation_detection_ghidra](https://github.com/mrphrazer/obfuscation_detection_ghidra).

Same idea as the original: run a bunch of heuristics that tend to light up
on obfuscated, packed, or crypto-heavy binaries. Matched functions get a
repeatable comment tagging why they were flagged, overlapping instructions
get highlighted, and everything is dumped to the Output window.

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
* Mixed boolean-arithmetic (needs Hex-Rays)
* Repeated CFG subgraphs

Utilities:

* Entry / leaf / recursive functions
* Section entropy
* RC4 KSA and PRGA candidates

## Install

Drop the loader and its package into your IDA user plugins dir:

```
~/.idapro/plugins/obfuscation_detection.py
~/.idapro/plugins/obfuscation_detection_ida/
```

On Windows the equivalent path is `%APPDATA%\Hex-Rays\IDA Pro\plugins\`.

Restart IDA. You should see `[obfdet] Obfuscation Detection 1.0 loaded.` in
the Output window. Heuristics show up under **Edit > Plugins > Obfuscation
Detection**. Running the plugin directly (without picking a submenu item)
runs everything.

## Using it

Menu: pick whatever you want from the submenu.

From the scripting console:

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

Headless (batch analysis over a folder of samples etc):

```
idat -A -Sscripts/detect_obfuscation.py <binary>
```

Tags show up as lines like `[obfdet] Heuristic: State Machine: ...`
inside each matched function's repeatable comment. Grep-friendly, survives
IDB saves, and running the same heuristic twice replaces the previous line
instead of stacking duplicates.

## Notes about the port

A few things differ from the Binary Ninja original because IDA's SDK doesn't
expose the same primitives:

* No first-class tag types in IDA. Findings go into the function's
  repeatable comment, prefixed with `[obfdet]`.
* Dominators, dominance frontiers, and back-edge detection are computed
  by the plugin (Cooper-Harvey-Kennedy). IDA's `FlowChart` doesn't hand
  those to you.
* Mixed boolean-arithmetic detection uses Hex-Rays microcode. If you don't
  have the decompiler installed the heuristic just returns 0 for every
  function rather than blowing up.
* The uncommon-instruction heuristic only runs on x86, x86_64, ARM, and
  AArch64. Other architectures get skipped with a message.

## Credit

All the actual research and heuristics come from Tim Blazytko's original
[obfuscation_detection](https://github.com/mrphrazer/obfuscation_detection).
See also his BlackHat / RECON talks on the topic if you want the background.

## License

GPL-2.0, matching the upstream project.
