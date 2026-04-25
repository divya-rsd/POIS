# PA#1 Usage Guide

This folder contains Part 1 implementation in [owf_prg.py](owf_prg.py).

## What Part 1 includes

- DLP-based OWF: `f(x) = g^x mod p`
- AES-based OWF: `f(k) = AES_k(0^128) XOR k`
- PRG from OWF (forward reduction)
- OWF from PRG (backward reduction)
- Statistical checks: monobit, runs, serial

## How to run

From the project root:

```bash
python3 pa1/owf_prg.py
```

You should see sections for:

1. OWF DLP evaluation and hardness demo
2. OWF AES evaluation
3. PRG generation output
4. Statistical tests with PASS/FAIL
5. Backward reduction demo (bounded brute-force search)

## How to run with all assignments

```bash
python3 run_all.py
```

PA#1 is the first suite called by the global runner.

## Notes

- Use `python3` (not `python`) on systems where `python` is not aliased.
- The backward hardness demo uses bounded attempts so scripts finish quickly.
- Parameters are intentionally lightweight for coursework/demo speed, not production cryptography.

## If you want stronger/longer tests

You can tune the backward demo in [owf_prg.py](owf_prg.py):

- `max_attempts` inside `demonstrate_hardness(...)`
- `output_bits` inside `demonstrate_hardness(...)`

Higher values make the demonstration slower.
