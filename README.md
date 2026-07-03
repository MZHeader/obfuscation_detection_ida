# Obfuscation Detection (IDA Pro)

An IDA Pro port of Tim Blazytko's [Obfuscation Detection](https://github.com/mrphrazer/obfuscation_detection)
Binary Ninja plugin. It looks for constructs that frequently appear in
obfuscated / packed / crypto-heavy binaries and either prints them to the
Output window, tags the containing function with a repeatable comment, or
highlights the relevant bytes in the disassembly view.

## Heuristics

- **State Machine** — control-flow flattening / dispatcher-style loops.
- **Complex Function** — cyclomatic complexity ranking.
- **Large Basic Block** — unusually large blocks (unrolled crypto etc.).
- **Overlapping Instruction** — bytes decoded as more than one instruction.
- **Uncommon Instruction Sequence** — rare 3-grams versus reference tables
  for x86, x86_64, ARM and AArch64.
- **Most Called Function** — helpers with many call sites (string decryption
  routines, statically-linked crypto…).
- **Loop Frequency** — number of natural loops per function.
- **Irreducible Loop** — SCCs that aren't natural loops.
- **XOR Decryption Loop** — XOR-by-constant inside a loop.
- **Complex Arithmetic Expression** — mixed boolean/arithmetic microcode
  instructions (requires Hex-Rays).
- **Duplicate Subgraph** — repeated CFG substructures inside a function.

## Utility detections

- Entry / leaf / recursive functions.
- Section (segment) entropy ranking.
- Candidate RC4 KSA / PRGA implementations.

## Install

Copy the plugin loader **and** the sibling package into your IDA user
plugins directory:

```
~/.idapro/plugins/obfuscation_detection.py
~/.idapro/plugins/obfuscation_detection_ida/
```

(On Windows the equivalent is `%APPDATA%\Hex-Rays\IDA Pro\plugins\`.)

Restart IDA. The plugin registers actions under **Edit > Plugins >
Obfuscation Detection**, and it can also be invoked directly through
**Edit > Plugins > Obfuscation Detection** which runs every heuristic.

## Usage

- Menu-driven: pick a heuristic from the submenu.
- Programmatic: from the IDA scripting console or an IDAPython script

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

- Headless: `scripts/detect_obfuscation.py` can be invoked with
  `idat -A -Sdetect_obfuscation.py <binary>` for CI-style batch runs.

Each heuristic tags matched functions by appending an `[obfdet]`-prefixed
line to the function's repeatable comment; running a heuristic twice
overwrites its previous line rather than duplicating it.

## Notes vs. the Binary Ninja original

- IDA has no first-class tag types, so tags are encoded in the function's
  repeatable comment (`Ctrl-;`). This is greppable and survives IDB saves.
- Mixed-boolean-arithmetic detection uses the Hex-Rays microcode; if the
  decompiler is not available the heuristic returns 0 for every function.
- Dominator, dominance-frontier and back-edge computations are done inside
  the plugin because the IDA SDK does not expose them directly.
