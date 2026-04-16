#!/usr/bin/env python3
"""
Master Test Runner 
Run: python run_all.py
"""
import sys, os, time, traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

RESULTS = []

def run(name, fn):
    print(f"\n{'═'*62}")
    t0 = time.time()
    try:
        fn()
        elapsed = round(time.time()-t0, 3)
        RESULTS.append((name, '✓ PASS', elapsed))
        print(f"  ⏱  {elapsed}s")
    except Exception as e:
        elapsed = round(time.time()-t0, 3)
        RESULTS.append((name, f'✗ FAIL: {e}', elapsed))
        traceback.print_exc()

def main():
    print("\n" + "═"*62)
    print("  CS8.401 Principles of Information Security")
    print("  Comprehensive Assignment Test Suite")
    print("═"*62)

    from pa1.owf_prg import demo as d1
    from pa2.prf_ggm import demo as d2
    from pa3.cpa_enc import demo as d3
    from pa4.modes import demo as d4
    from pa5.mac import demo as d5
    from pa6.cca_enc import demo as d6
    from pa7.merkle_damgard import demo as d7
    from pa8_9_10.hash_hmac import demo_pa8, demo_pa9, demo_pa10
    from pa11.dh import demo as d11
    from pa12.rsa import demo as d12
    from pa13.primality import demo as d13
    from pa14_15_16.crt_sig_elgamal import demo_pa14, demo_pa15, demo_pa16
    from pa17_18_19_20.mpc import demo_pa17, demo_pa18, demo_pa19, demo_pa20

    run("PA#1  OWF + PRG", d1)
    run("PA#2  PRF (GGM)", d2)
    run("PA#3  CPA-Enc", d3)
    run("PA#4  Modes", d4)
    run("PA#5  MAC", d5)
    run("PA#6  CCA-Enc", d6)
    run("PA#7  Merkle-Damgård", d7)
    run("PA#8  DLP Hash", demo_pa8)
    run("PA#9  Birthday Attack", demo_pa9)
    run("PA#10 HMAC + EtH", demo_pa10)
    run("PA#11 Diffie-Hellman", d11)
    run("PA#12 RSA + PKCS1v15", d12)
    run("PA#13 Miller-Rabin", d13)
    run("PA#14 CRT + Håstad", demo_pa14)
    run("PA#15 Digital Signatures", demo_pa15)
    run("PA#16 ElGamal", demo_pa16)
    run("PA#17 CCA-PKC", demo_pa17)
    run("PA#18 Oblivious Transfer", demo_pa18)
    run("PA#19 Secure AND", demo_pa19)
    run("PA#20 2-Party MPC", demo_pa20)

    # Summary
    print("\n" + "═"*62)
    print("  SUMMARY")
    print("═"*62)
    passed = sum(1 for _,s,_ in RESULTS if s.startswith('✓'))
    total = len(RESULTS)
    for name,status,elapsed in RESULTS:
        print(f"  {status[:8]:10s} {name:30s} {elapsed}s")
    print(f"\n  {passed}/{total} assignments passed")
    print("═"*62)

if __name__ == "__main__":
    main()
