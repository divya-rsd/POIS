# PA#1 Usage Guide

This folder contains Part 1 implementation in [owf_prg.py](owf_prg.py).

## What Part 1 includes

- DLP-based OWF: `f(x) = g^x mod p`
- PRG from OWF (forward reduction)
- OWF from PRG (backward reduction)
- Statistical checks: monobit, runs, serial
- Black-box PRG interface: `seed(s)`, `next_bits(n)`, `expand(seed, ell_bits)`

## How to run

From the project root:

```bash
python3 pa1/owf_prg.py
```

You should see sections for:

1. OWF DLP evaluation and hardness demo
2. PRG generation output (`n + ell` bits, no seed leakage)
3. Statistical tests with PASS/FAIL
4. Backward reduction demo (bounded brute-force search)

You will also see a PRG determinism check (`[2.1]`) that verifies:

- Same seed -> same output
- Different seed -> different output

## How to run with all assignments

```bash
python3 run_all.py
```

PA#1 is the first suite called by the global runner.

## Notes

- Use `python3` (not `python`) on systems where `python` is not aliased.
- The backward hardness demo uses bounded attempts so scripts finish quickly.
- Parameters are intentionally lightweight for coursework/demo speed, not production cryptography.
- The OWF used for PA#1 is DLP-based only.

## If you want stronger/longer tests

You can tune the backward demo in [owf_prg.py](owf_prg.py):

- `trials`, `max_attempts`, and `ell_bits` inside `verify_hardness(...)`
- Or use the compatibility wrapper `demonstrate_hardness(...)`

Higher values make the demonstration slower.
