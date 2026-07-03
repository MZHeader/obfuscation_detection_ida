# Obfuscation Detection for IDA Pro

> Port of [mrphrazer/obfuscation_detection](https://github.com/mrphrazer/obfuscation_detection)
> by [Tim Blazytko](https://github.com/mrphrazer).

Same idea as the original but for IDA Pro. The plugin flags functions
whose shape suggests something interesting is going on: obfuscated
control flow, state machines and protocol dispatchers, C2 communication,
string or code decryption stubs, and hand-rolled cryptography. Each
heuristic scores on a different signal; the results table ranks by how
many independent heuristics hit the same function, so real obfuscation
floats above one-off matches. Findings also land in function comments
and get logged to the Output window.

## What it looks for

Heuristics:

* State machines / control-flow flattening
* High cyclomatic complexity
* Unusually large basic blocks
* Overlapping instructions (bytes decoded as more than one instruction)
* Rare 3-gram opcode sequences (scored against a reference table per arch)
* Popular helpers (functions called from many places, often string decryptors or API-hash resolvers)
* Functions with many natural loops
* Irreducible loops
* XOR-by-constant inside a loop
* Mixed boolean-arithmetic
* Repeated CFG subgraphs (cloned obfuscation stubs, unrolled loops)
* Basic-block splitting (high blocks-per-branch ratio)

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
**Edit > Plugins > Obfuscation Detection**. Launching it opens the dockable
results table and a menu pops up listing every heuristic. Pick one to run
and its findings populate the same table.

![Chooser dialog](imgs/chooser.png)

The results table has one row per function, sorted by how many heuristics
fired. Double-clicking a row jumps to that function. **Configure: Findings
Cap** in the chooser adjusts the per-heuristic result cap (default 30).

![Results view](imgs/results.png)

Findings are added as a comment: `[obfdet] Heuristic: State Machine: ...`. 

Comments can be mass-removed by selecting the `Clear all [obfdet] comments` option.

## Notes about the port

### 1. Tuned defaults

The scoring formulas match upstream but every heuristic has a minimum
threshold, so borderline hits don't reach the results table. Upstream
reports each heuristic's top ~10% unconditionally; here you get the top
30 that also clear a floor.

* Cyclomatic complexity: `>= 50` and `>= 20` blocks
* Average instructions per block: `>= 40`
* Duplicate subgraphs: `>= 4` copies
* Uncommon 3-gram score: `>= 0.85` over `>= 30` sequences
* Loop count: `>= 5`
* MBA: `>= 5` mixed instructions, function in a 3-200 block band,
  Go/Rust runtime shims that crash `gen_microcode` skipped by name
* State machines: `>= 3`-way dispatcher inside a loop, with a separate
  path for binary-comparison flattening cascades
* XOR-in-loop: trivial constants skipped (0, +/-1, all-Fs, sign-bit
  masks, 25-31-bit bignum limb masks used in constant-time compares);
  constants appearing in `>= 3` functions across the binary are dropped
  as compile-time magic rather than decryption keys
* Popular helpers only surface if they also contain a XOR decryption
  loop, which targets string decryptors and API-hash resolvers instead
  of `printf`-shaped hot calls
* Library and thunk functions are skipped before scoring
* RC4 KSA/PRGA candidates require both the `0x100` initialisation and
  an S-box byte lookup inside a natural loop, which drops most AES,
  HMAC, and `memcmp` false positives

### 2. SDK differences

IDA's SDK doesn't give you the same primitives as Binary Ninja, so a
few things are handled differently:

* IDA has no first-class tag types. Findings land in function and
  instruction comments, prefixed with `[obfdet]`.
* Dominators, dominance frontiers, and back-edge detection are computed
  inside the plugin (Cooper-Harvey-Kennedy). IDA's `FlowChart` doesn't
  give you any of that.
* XOR-in-loop and RC4 PRGA detection walk assembly mnemonics rather than
  a lifted IL. IDA has no LLIL equivalent that works without the
  decompiler, so plain `xor` / `eor` patterns get caught but anything
  hidden inside a lifted arithmetic identity does not.
* Mixed-boolean-arithmetic detection uses Hex-Rays microcode at
  `MMAT_LVARS`. Without Hex-Rays it prints a warning and skips the
  heuristic. `gen_microcode` has crashed IDA on some Go binaries during
  testing, so MBA is left out of `run_all`; run it on its own from the
  chooser when you want it.
* Uncommon-instruction-sequence only runs on x86, x86_64, ARM, and
  AArch64. Other architectures get a "no n-gram table" message and are
  skipped rather than falling through to something meaningless.
* The results dock tries PySide6, then PySide2, then PyQt5. If none of
  them import, the plugin still tags functions and logs to the Output
  window; only the dock is unavailable.