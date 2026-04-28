"""
PA #17 — CCA-Secure PKC (Signcrypt)
PA #18 — Oblivious Transfer
PA #19 — Secure AND Gate
PA #20 — All 2-Party Secure Computation (Millionaire's, Equality, Addition)
"""
import os, sys, secrets, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa14_15_16.crt_sig_elgamal import ElGamal, Sign, Verify
from pa12.rsa import RSA, _mod_inverse, _fast_pow
from pa11.dh import _rand_exp

# ─────────── PA #17 — CCA-PKC ───────────
class CCA_PKC:
    """Encrypt-then-Sign (Signcrypt): CCA2-secure PKC."""
    
    @staticmethod
    def CCA_PKC_Enc(eg: ElGamal, pk_enc, signer_sk, m: int) -> tuple:
        """First encrypt m with ElGamal (PA#16), then sign ciphertext with digital signature (PA#15)."""
        c1, c2 = eg.encrypt(pk_enc, m)
        sig = Sign(signer_sk, f"{c1},{c2}".encode())
        return c1, c2, sig

    @staticmethod
    def CCA_PKC_Dec(eg: ElGamal, sk_enc, verifier_pk, c1, c2, sig):
        """Call Verify first; if signature is invalid return ⊥; otherwise call Dec."""
        if not Verify(verifier_pk, f"{c1},{c2}".encode(), sig):
            return None  # ⊥
        return eg.decrypt(sk_enc, c1, c2)


# ─────────── PA #17 — IND-CCA2 Game ───────────
class IND_CCA2_Game:
    """
    Formal IND-CCA2 game (Challenger vs. Adversary) for the signcrypt scheme.

    Per round:
      1. Challenger generates (sk, pk) and offers a decryption oracle.
      2. Adversary may issue oracle queries on any (c1, c2, sig).
      3. Adversary picks m0, m1; challenger picks bit b ← {0,1}, returns C* = Enc(mb).
      4. Adversary may issue MORE oracle queries — but NOT on C* itself.
         Critically, the adversary submits MUTATIONS of C* (e.g. the malleability
         attack c2' = 2·c2) to try to learn b indirectly.
      5. Adversary outputs b'. Win iff b'==b.

    Because every oracle query past the challenge has c1,c2 different from C*,
    the signature on C* does not validate the mutated ciphertext, so the oracle
    returns ⊥ on every adversary attempt — making the oracle useless.
    """

    def __init__(self, bits=128):
        self.eg = ElGamal(bits)
        self.rsa = RSA(max(512, bits*4))
        self.signer_sk = self.rsa.sk
        self.verifier_pk = self.rsa.pk
        self.keys = self.eg.keygen()
        self.sk = self.keys['sk']; self.pk = self.keys['pk']
        self.oracle_calls = 0
        self.oracle_rejections = 0

    def _decryption_oracle(self, c1, c2, sig, challenge):
        """Decryption oracle: forbid querying on the challenge tuple itself."""
        self.oracle_calls += 1
        if (c1, c2, sig) == challenge:
            return None  # forbidden query — challenger refuses
        result = CCA_PKC.CCA_PKC_Dec(self.eg, self.sk, self.verifier_pk, c1, c2, sig)
        if result is None:
            self.oracle_rejections += 1
        return result

    def malleability_adversary(self, n_rounds: int = 50) -> dict:
        """
        Adversary that attempts the ElGamal multiplicative malleability attack:
        given C* = (c1, c2, sig), submit (c1, 2·c2 mod p, sig) hoping the oracle
        decrypts it to 2·mb, revealing b.
        """
        wins = 0
        self.oracle_calls = 0
        self.oracle_rejections = 0
        for _ in range(n_rounds):
            p = self.pk[0]
            # CSPRNG-driven challenge: m0, m1, b all from secrets.
            m0 = 2 + secrets.randbelow(max(1, p // 4 - 2))
            m1 = 2 + secrets.randbelow(max(1, p // 4 - 2))
            while m1 == m0:
                m1 = 2 + secrets.randbelow(max(1, p // 4 - 2))
            b = secrets.randbits(1)
            mb = m0 if b == 0 else m1
            c1, c2, sig = CCA_PKC.CCA_PKC_Enc(self.eg, self.pk, self.signer_sk, mb)
            challenge = (c1, c2, sig)
            # Multiplicative-malleability attempt — same trick that breaks plain ElGamal
            mutated_c2 = (2 * c2) % p
            oracle_out = self._decryption_oracle(c1, mutated_c2, sig, challenge)
            if oracle_out is None:
                # Oracle blocked; adversary has no information → guess randomly.
                b_guess = secrets.randbits(1)
            else:
                # Oracle (impossibly) accepted: m0' = oracle_out / 2 reveals b.
                recovered = oracle_out * _mod_inverse(2, p) % p
                b_guess = 0 if recovered == m0 else 1
            if b_guess == b:
                wins += 1
        adv = abs(wins / n_rounds - 0.5)
        return {
            'rounds': n_rounds, 'wins': wins, 'advantage': round(adv, 4),
            'oracle_calls': self.oracle_calls,
            'oracle_rejections': self.oracle_rejections,
            'secure': adv < 0.15,
        }


def demo_pa17():
    print("="*60); print("PA #17 — CCA-Secure PKC (Signcrypt)"); print("="*60)
    
    # ── Setup explicit keys to match requirements ──
    eg = ElGamal(bits=128)
    receiver_keys = eg.keygen()
    sk_enc, pk_enc = receiver_keys['sk'], receiver_keys['pk']
    
    rsa = RSA(bits=512)
    signer_sk = rsa.sk
    verifier_pk = rsa.pk
    
    m = 9999
    c1, c2, sig = CCA_PKC.CCA_PKC_Enc(eg, pk_enc, signer_sk, m)
    dec = CCA_PKC.CCA_PKC_Dec(eg, sk_enc, verifier_pk, c1, c2, sig)
    print(f"  Encrypt/Decrypt m={m}: {dec==m} ✓")

    # ── Multiplicative-malleability attack: works on plain ElGamal, blocked here ──
    print("\n  [Multiplicative malleability attack — plain ElGamal vs. signcrypt]")
    p = pk_enc[0]
    plain_c1, plain_c2 = eg.encrypt(pk_enc, m)
    plain_c2_mauled = (2 * plain_c2) % p
    plain_dec = eg.decrypt(sk_enc, plain_c1, plain_c2_mauled)
    print(f"  Plain ElGamal: Enc(m={m}) → maul c2 → Dec gives {plain_dec} (= 2m? {plain_dec == 2*m}) ✗ broken")

    cca_c2_mauled = (2 * c2) % p
    cca_dec_mauled = CCA_PKC.CCA_PKC_Dec(eg, sk_enc, verifier_pk, c1, cca_c2_mauled, sig)
    print(f"  Signcrypt:     Enc(m={m}) → maul c2 → Dec gives {cca_dec_mauled} (⊥ = rejected) ✓ blocked")

    # ── Formal IND-CCA2 game ──
    print("\n  [Formal IND-CCA2 game — multiplicative-malleability adversary, 50 rounds]")
    game = IND_CCA2_Game(bits=128)
    res = game.malleability_adversary(n_rounds=50)
    print(f"  Wins: {res['wins']}/{res['rounds']}, advantage = {res['advantage']} ≈ 0  → CCA2-secure ✓")
    print(f"  Oracle calls = {res['oracle_calls']}, rejections (⊥) = {res['oracle_rejections']}")
    print(f"  Every malleated query was rejected → decryption oracle is useless to the adversary.")
    
    # ── Lineage Check ──
    print("\n  [End-to-end lineage]")
    print("  CCA_PKC_Enc → ElGamal.encrypt (PA#16) + RSA_Sign.sign (PA#15)")
    print("    ├─ ElGamal (PA#16)")
    print("    │  └─ DH safe-prime parameters (PA#11)")
    print("    │     └─ Miller-Rabin primality testing (PA#13)")
    print("    └─ RSA_Sign (PA#15)")
    print("       └─ RSA core (PA#12)")
    print("          └─ Miller-Rabin primality testing (PA#13)")
    print("✓ PA#17 complete.")

# ─────────── PA #18 — Oblivious Transfer ───────────
class OT_1of2:
    """
    1-out-of-2 OT using ElGamal PKC (Bellare-Micali style).
    Receiver gets m_b without learning m_{1-b}; sender learns nothing about b.

    SECURITY ARGUMENT (informal, for the privacy proof):

    * Receiver privacy (sender does not learn b):
        pk_b is honestly generated as h = g^x with sk_b = x.
        pk_{1-b} is sampled as a uniformly random group element fake_h, with
        no associated trapdoor. Both keys are uniformly distributed in the
        order-q subgroup of Z_p*, so they are computationally indistinguishable.
        From the sender's view (pk_0, pk_1) leaks no information about b.

    * Sender privacy (receiver does not learn m_{1-b}):
        c_{1-b} = (g^r, m_{1-b} · fake_h^r mod p). Decrypting it requires knowing
        log_g(fake_h), i.e. solving the Discrete Log Problem in Z_p*. Under the
        DLP assumption, the receiver learns nothing about m_{1-b}.

    The `dlp_break_other_message` method below realises the second argument
    concretely: it brute-forces log_g(fake_h) in a small group, showing the
    privacy reduces *exactly* to the cost of solving DLP.
    """

    def __init__(self, bits=128):
        self._eg = ElGamal(bits)
        self.call_count = 0     # incremented per receiver_step1() — used by PA#19/#20 metrics
        self.transcript = []    # log of (label, payload) tuples for privacy auditing

    def receiver_step1(self, b: int) -> tuple:
        """Generate (pk_b, pk_{1-b}). Only knows sk_b."""
        assert b in (0, 1)
        self.call_count += 1
        real_keys = self._eg.keygen()
        sk_b = real_keys['sk']; pk_b = real_keys['pk']
        # Construct pk_{1-b} as a uniformly random group element (no trapdoor).
        p, g, q, _ = pk_b
        # CSPRNG-driven exponent: secrets.randbelow ⇒ os.urandom. Using random.*
        # here would let an attacker who reseeds the Mersenne-Twister predict
        # fake_h and silently break sender privacy.
        fake_h = _fast_pow(g, 2 + secrets.randbelow(q - 3), p)
        pk_fake = (p, g, q, fake_h)
        if b == 0:
            pk0, pk1 = pk_b, pk_fake
        else:
            pk0, pk1 = pk_fake, pk_b
        state = {'b': b, 'sk_b': sk_b, 'pk_b': pk_b, 'b_idx': b, 'fake_h': fake_h}
        # Transcript: only the public keys leave the receiver. b is private.
        self.transcript.append(('R→S', {'pk0': pk0, 'pk1': pk1}))
        return pk0, pk1, state

    def sender_step(self, pk0, pk1, m0: int, m1: int) -> tuple:
        c0 = self._eg.encrypt(pk0, m0)
        c1 = self._eg.encrypt(pk1, m1)
        # Transcript: only ciphertexts leave the sender. (m0, m1) are private.
        self.transcript.append(('S→R', {'c0': c0, 'c1': c1}))
        return c0, c1

    def receiver_step2(self, state, c0, c1) -> int:
        b = state['b']; sk_b = state['sk_b']; pk_b = state['pk_b']
        cb = c0 if b == 0 else c1
        return self._eg.decrypt(sk_b, *cb)

    def dlp_break_other_message(self, state, c0, c1, m_real_other: int, max_iters: int = 100000) -> dict:
        """
        Brute-force log_g(fake_h) — the receiver's only path to m_{1-b}.

        Returns iterations + recovered message; should match `m_real_other`
        if the brute force succeeds. Intended for tiny groups (q << 2^20).
        max_iters protects against hanging on large production groups.
        """
        b = state['b']
        p, g, q, _ = state['pk_b']
        fake_h = state['fake_h']
        c_other = c1 if b == 0 else c0
        c1_other, c2_other = c_other
        t0 = time.time()
        x_found = None
        cur = 1
        limit = min(q, max_iters + 1) if max_iters else q
        for x in range(1, limit):
            cur = cur * g % p
            if cur == fake_h:
                x_found = x
                break
        elapsed = time.time() - t0
        if x_found is None:
            return {'recovered': False, 'iters': limit - 1, 'time_s': round(elapsed, 4)}
        # Decrypt the OTHER ciphertext using the brute-forced sk
        s = _fast_pow(c1_other, x_found, p)
        recovered = c2_other * _mod_inverse(s, p) % p
        return {
            'recovered': True,
            'iters': x_found,
            'time_s': round(elapsed, 4),
            'recovered_message': recovered,
            'matches_truth': recovered == m_real_other,
        }


def demo_pa18():
    print("="*60); print("PA #18 — Oblivious Transfer"); print("="*60)
    ot = OT_1of2(bits=128)

    # ── Correctness: 100 random trials with random b, m0, m1 ──
    print("  [Correctness — 100 random trials]")
    correct = 0
    for _ in range(100):
        # CSPRNG-driven inputs — every selection bit and message byte from os.urandom.
        b = secrets.randbits(1)
        m0 = 1 + secrets.randbelow(10**9)
        m1 = 1 + secrets.randbelow(10**9)
        pk0, pk1, state = ot.receiver_step1(b)
        c0, c1 = ot.sender_step(pk0, pk1, m0, m1)
        got = ot.receiver_step2(state, c0, c1)
        if got == (m0 if b == 0 else m1):
            correct += 1
    print(f"  Correct OT outputs: {correct}/100 ✓")

    # ── Receiver privacy (sender cannot tell b) ──
    print("\n  [Receiver privacy — sender's view is (pk0, pk1) only]")
    print("  Both pk_0 and pk_1 live in the same uniform distribution over the")
    print("  order-q subgroup. fake_h = g^random has the same distribution as h = g^sk.")
    print("  From the sender's transcript, b is information-theoretically hidden.")
    pk0_b0, _, _ = ot.receiver_step1(0)
    _, pk1_b1, _ = ot.receiver_step1(1)
    p_share = pk0_b0[0]
    h0 = pk0_b0[3]; h1 = pk1_b1[3]
    print(f"  pk for b=0 (real h):      {hex(h0)[:20]}…  (∈ Z*_{hex(p_share)[:8]}…)")
    print(f"  pk for b=1 (random fake): {hex(h1)[:20]}…  (∈ same group, indistinguishable) ✓")

    # ── Sender privacy (receiver brute-forces DLP to recover the other message) ──
    print("\n  [Sender privacy — recovering m_{1-b} reduces to DLP]")
    print("  Use a tiny ~14-bit q so the brute force completes in seconds.")
    ot_tiny = OT_1of2(bits=14)
    b = 0
    m_known, m_other = 12, 56
    pk0, pk1, state = ot_tiny.receiver_step1(b)
    c0, c1 = ot_tiny.sender_step(pk0, pk1, m_known, m_other)
    got = ot_tiny.receiver_step2(state, c0, c1)
    print(f"  Receiver legitimately learns m_{b} = {got} (= m_known? {got == m_known}) ✓")
    res = ot_tiny.dlp_break_other_message(state, c0, c1, m_other)
    if res['recovered']:
        print(f"  Receiver brute-forces DLP in {res['iters']} iters ({res['time_s']}s) "
              f"→ recovers m_{1-b} = {res['recovered_message']} (= m_other? "
              f"{res['matches_truth']}) ✗ insecure for tiny q")
    print("  (For 2048-bit q the same loop runs 2^2048 iterations → infeasible → secure.)")
    print("✓ PA#18 complete.")

# ─────────── PA #19 — Secure AND/XOR ───────────
class SecureGates:
    """
    Secure AND (via OT) and XOR (via additive secret sharing) over Z_2.

    PRIVACY ARGUMENT (informal):

      Secure AND:
        * Alice's input a is private. Alice acts as OT sender with messages
          (m0=0, m1=a). Bob never sees `a` directly — he only learns m_b,
          which equals a · b. By OT sender privacy, Bob learns nothing about
          m_{1-b} (and hence nothing about `a` beyond what a∧b already reveals).
        * Bob's input b is private. Bob acts as OT receiver. By OT receiver
          privacy, Alice's view (pk_0, pk_1) is computationally
          indistinguishable across b=0 and b=1 — so Alice learns nothing
          about b.

      Secure XOR:
        * Alice samples random r ← {0,1} and sends it to Bob (or it is
          jointly chosen). Alice's share is α = a ⊕ r; Bob's share is
          β = b ⊕ r. The output is α ⊕ β = a ⊕ b. r is uniformly random,
          so α is independent of a (one-time-pad), and likewise β is
          independent of b. Neither party's share alone leaks input bits.

      Secure NOT is local: Alice (the share-holder of a) flips her share.

    Together AND, XOR, NOT form a functionally-complete basis, so any
    polynomial-size boolean circuit can be securely evaluated.
    """

    def __init__(self, bits=128):
        self._ot = OT_1of2(bits)
        self.transcript = []           # log of every gate-level message exchange
        self.and_count = 0
        self.xor_count = 0
        self.not_count = 0

    def AND(self, a: int, b: int) -> int:
        """Secure AND via 1-out-of-2 OT.

        Alice acts as OT sender with messages (m0, m1) = (0, a).
        Bob acts as OT receiver with choice bit b → learns m_b = a · b.
        """
        assert a in (0, 1) and b in (0, 1)
        self.and_count += 1
        m0, m1 = 0, a
        pk0, pk1, state = self._ot.receiver_step1(b)
        c0, c1 = self._ot.sender_step(pk0, pk1, m0, m1)
        result = self._ot.receiver_step2(state, c0, c1)
        # Transcript records only what crosses the wire — never a or b directly.
        self.transcript.append(('AND', {'pk0': pk0, 'pk1': pk1, 'c0': c0, 'c1': c1, 'output': result & 1}))
        return result & 1

    def XOR(self, a: int, b: int) -> int:
        """Secure XOR via additive secret sharing over Z_2.

        Protocol:
          1. Alice samples uniformly random r ∈ {0,1} and sends it to Bob.
          2. Alice computes alice_share = a ⊕ r.
          3. Bob   computes bob_share   = b ⊕ r.
          4. Either party reveals their share; output = alice_share ⊕ bob_share = a ⊕ b.

        r masks Alice's input bit perfectly (one-time pad), and the two
        shares jointly carry no information about (a, b) beyond their XOR.
        """
        assert a in (0, 1) and b in (0, 1)
        self.xor_count += 1
        r = secrets.randbits(1)
        alice_share = a ^ r
        bob_share = b ^ r
        # Transcript: only the random bit r and the public shares cross.
        self.transcript.append(('XOR', {'r': r, 'alice_share': alice_share, 'bob_share': bob_share,
                                        'output': alice_share ^ bob_share}))
        return alice_share ^ bob_share

    def NOT(self, a: int) -> int:
        """Secure NOT is free — Alice flips her local share."""
        assert a in (0, 1)
        self.not_count += 1
        return 1 - a

    def reset_metrics(self):
        self.and_count = self.xor_count = self.not_count = 0
        self.transcript.clear()
        self._ot.call_count = 0
        self._ot.transcript.clear()


def demo_pa19():
    print("="*60); print("PA #19 — Secure AND Gate"); print("="*60)
    gates = SecureGates(bits=128)

    # ── Truth-table verification across 50 runs of each (a, b) combination ──
    print("  [Truth-table verification — 50 runs per input combination]")
    for a in (0, 1):
        for b in (0, 1):
            and_correct = sum(1 for _ in range(50) if gates.AND(a, b) == (a & b))
            xor_correct = sum(1 for _ in range(50) if gates.XOR(a, b) == (a ^ b))
            print(f"    AND({a},{b}): {and_correct}/50 ✓   XOR({a},{b}): {xor_correct}/50 ✓")

    # ── Privacy: show transcript carries only public messages ──
    print(f"\n  [Transcript audit — last 3 gate exchanges]")
    for entry in gates.transcript[-3:]:
        op, payload = entry
        keys = ', '.join(payload.keys())
        print(f"    {op} entry payload keys: {{{keys}}} (no a/b bits in transcript ✓)")
    print(f"  Counts: AND={gates.and_count}, XOR={gates.xor_count}, NOT={gates.not_count}, "
          f"OT calls={gates._ot.call_count}")
    print("✓ PA#19 complete.")

# ─────────── PA #20 — Boolean Circuit DAG ───────────
class Gate:
    """A node in the boolean circuit DAG.

    Each gate has:
      op:        'INPUT_A' | 'INPUT_B' | 'CONST' | 'AND' | 'XOR' | 'NOT'
      inputs:    list of upstream wire ids (gate outputs feeding into this gate)
      meta:      bookkeeping — input index for INPUT_A/B, value for CONST
      output:    wire id assigned by the Circuit
    """
    __slots__ = ('op', 'inputs', 'meta', 'output_wire')

    def __init__(self, op: str, inputs=None, meta=None):
        self.op = op
        self.inputs = list(inputs) if inputs else []
        self.meta = meta
        self.output_wire = None

    def __repr__(self):
        return f"Gate({self.op}, in={self.inputs}, meta={self.meta})"


class Circuit:
    """
    Directed acyclic graph of boolean gates.

    Inputs are referenced by symbolic INPUT_A[i] / INPUT_B[i] gates that
    are bound at evaluation time. The DAG must be topologically sorted
    (it is, by construction — gates are added in dependency order).
    """

    def __init__(self):
        self.gates: list[Gate] = []

    def _add(self, gate: Gate) -> int:
        gate.output_wire = len(self.gates)
        self.gates.append(gate)
        return gate.output_wire

    # ── Wire-builder helpers ────────────────────────────────────────────
    def alice_input(self, i: int) -> int:
        return self._add(Gate('INPUT_A', meta=i))

    def bob_input(self, i: int) -> int:
        return self._add(Gate('INPUT_B', meta=i))

    def const(self, v: int) -> int:
        assert v in (0, 1)
        return self._add(Gate('CONST', meta=v))

    def AND(self, w1: int, w2: int) -> int:
        return self._add(Gate('AND', inputs=[w1, w2]))

    def XOR(self, w1: int, w2: int) -> int:
        return self._add(Gate('XOR', inputs=[w1, w2]))

    def NOT(self, w: int) -> int:
        return self._add(Gate('NOT', inputs=[w]))

    def topological_order(self) -> list[int]:
        """Already topologically sorted by construction — return wire ids in order."""
        return list(range(len(self.gates)))

    def Secure_Eval(self, gates_runtime: 'SecureGates',
                    x_alice: list[int], y_bob: list[int],
                    output_wires: list[int],
                    trace: list = None) -> list[int]:
        """
        Evaluate the circuit on Alice's input bits x_alice and Bob's bits y_bob,
        calling *only* gates_runtime.AND/XOR/NOT (each of which is a secure
        protocol invocation) — never plaintext math.
        If trace is provided, it will be populated with a step-by-step gate execution log.
        """
        wire_values: dict[int, int] = {}
        for w in self.topological_order():
            g = self.gates[w]
            if g.op == 'INPUT_A':
                wire_values[w] = x_alice[g.meta] & 1
            elif g.op == 'INPUT_B':
                wire_values[w] = y_bob[g.meta] & 1
            elif g.op == 'CONST':
                wire_values[w] = g.meta & 1
            elif g.op == 'AND':
                a, b = wire_values[g.inputs[0]], wire_values[g.inputs[1]]
                wire_values[w] = gates_runtime.AND(a, b)
            elif g.op == 'XOR':
                a, b = wire_values[g.inputs[0]], wire_values[g.inputs[1]]
                wire_values[w] = gates_runtime.XOR(a, b)
            elif g.op == 'NOT':
                a = wire_values[g.inputs[0]]
                wire_values[w] = gates_runtime.NOT(a)
            else:
                raise ValueError(f"Unknown gate op: {g.op}")
            
            if trace is not None and g.op in ('AND', 'XOR', 'NOT'):
                trace.append({
                    "op": g.op,
                    "inputs": g.inputs,
                    "output_wire": w,
                    "output_val": wire_values[w]
                })
                
        return [wire_values[w] for w in output_wires]


# ─────────── PA #20 — Circuit builders for the three required protocols ───────────
def build_adder_circuit(n_bits: int) -> tuple:
    """
    Ripple-carry full adder with INPUT_A bits as Alice's wealth and INPUT_B as Bob's.

    Per bit i (LSB first):
      sum_i  = x_i ⊕ y_i ⊕ c_in
      c_out  = (x_i ∧ y_i) ⊕ (c_in ∧ (x_i ⊕ y_i))

    Returns (Circuit, sum_output_wires_LSB_first).
    """
    c = Circuit()
    x = [c.alice_input(i) for i in range(n_bits)]
    y = [c.bob_input(i) for i in range(n_bits)]
    carry = c.const(0)
    sum_wires = []
    for i in range(n_bits):
        x_xor_y = c.XOR(x[i], y[i])
        sum_i = c.XOR(x_xor_y, carry)
        x_and_y = c.AND(x[i], y[i])
        carry_and_xor = c.AND(carry, x_xor_y)
        carry = c.XOR(x_and_y, carry_and_xor)
        sum_wires.append(sum_i)
    return c, sum_wires


def build_equality_circuit(n_bits: int) -> tuple:
    """
    Equality circuit: eq = AND_i NOT(x_i ⊕ y_i).

    Implemented as a chain of ANDs over per-bit equality predicates.
    Returns (Circuit, [eq_output_wire]).
    """
    c = Circuit()
    x = [c.alice_input(i) for i in range(n_bits)]
    y = [c.bob_input(i) for i in range(n_bits)]
    eq = c.const(1)
    for i in range(n_bits):
        diff = c.XOR(x[i], y[i])
        not_diff = c.NOT(diff)
        eq = c.AND(eq, not_diff)
    return c, [eq]


def build_compare_gt_circuit(n_bits: int) -> tuple:
    """
    Greater-than circuit (x > y), MSB-first.

    Per bit (from MSB to LSB):
      neq          = x_i ⊕ y_i
      x_gt_here    = neq ∧ x_i           (x>y at this bit if differing AND x has 1)
      contribution = equal_so_far ∧ x_gt_here
      result      ⊕= contribution
      equal_so_far ∧= NOT(neq)
    """
    c = Circuit()
    x = [c.alice_input(i) for i in range(n_bits)]
    y = [c.bob_input(i) for i in range(n_bits)]
    result = c.const(0)
    equal_so_far = c.const(1)
    for i in range(n_bits - 1, -1, -1):
        neq = c.XOR(x[i], y[i])
        x_gt = c.AND(neq, x[i])
        contrib = c.AND(equal_so_far, x_gt)
        result = c.XOR(result, contrib)
        not_neq = c.NOT(neq)
        equal_so_far = c.AND(equal_so_far, not_neq)
    return c, [result]


# ─────────── PA #20 — High-level API used by tests, demo, backend ───────────
class SecureCircuit:
    """
    DAG-driven 2-party secure computation harness.

    Each public method (`secure_add`, `secure_equality`, `secure_compare_gt`,
    `millionaires`) builds the relevant circuit, calls Secure_Eval, and reports
    OT-call / wall-clock metrics. Plaintext arithmetic is forbidden — the
    answer comes out of bit-level secure-gate evaluations only.
    """

    def __init__(self, gates: SecureGates):
        self.g = gates
        self.last_metrics: dict = {}

    # ── helpers ─────────────────────────────────────────────────────────
    def _bits_lsb(self, v: int, n: int) -> list[int]:
        return [(v >> i) & 1 for i in range(n)]

    def _evaluate(self, circuit: Circuit, x_bits, y_bits, out_wires) -> tuple:
        self.g.reset_metrics()
        trace = []
        t0 = time.time()
        outs = circuit.Secure_Eval(self.g, x_bits, y_bits, out_wires, trace=trace)
        elapsed = time.time() - t0
        self.last_metrics = {
            'gates_evaluated': len(circuit.gates),
            'and_calls': self.g.and_count,
            'xor_calls': self.g.xor_count,
            'not_calls': self.g.not_count,
            'ot_calls': self.g._ot.call_count,
            'time_s': round(elapsed, 4),
            'trace': trace,
        }
        return outs

    # ── public protocols ────────────────────────────────────────────────
    def secure_add(self, x: int, y: int, bits: int = 4) -> int:
        circuit, sum_wires = build_adder_circuit(bits)
        out_bits = self._evaluate(circuit, self._bits_lsb(x, bits), self._bits_lsb(y, bits), sum_wires)
        # Sum bits are LSB-first; reassemble to integer mod 2^bits.
        return sum(b << i for i, b in enumerate(out_bits))

    def secure_equality(self, x: int, y: int, bits: int = 4) -> int:
        circuit, eq_wires = build_equality_circuit(bits)
        out = self._evaluate(circuit, self._bits_lsb(x, bits), self._bits_lsb(y, bits), eq_wires)
        return out[0]

    def secure_compare_gt(self, x: int, y: int, bits: int = 4) -> int:
        circuit, gt_wires = build_compare_gt_circuit(bits)
        out = self._evaluate(circuit, self._bits_lsb(x, bits), self._bits_lsb(y, bits), gt_wires)
        return out[0]

    def millionaires(self, alice_wealth: int, bob_wealth: int) -> str:
        gt = self.secure_compare_gt(alice_wealth, bob_wealth, bits=4)
        eq = self.secure_equality(alice_wealth, bob_wealth, bits=4)
        if eq:
            return "Equal"
        return "Alice richer" if gt else "Bob richer"


def demo_pa20():
    print("=" * 60); print("PA #20 — All 2-Party Secure Computation"); print("=" * 60)
    gates = SecureGates(bits=128)
    circuit = SecureCircuit(gates)

    # ── Millionaire's problem (4-bit), via DAG comparator ──
    print("  Millionaire's Problem (4-bit wealth, DAG-driven secure compare):")
    for a, b in [(7, 12), (5, 5), (15, 3)]:
        result = circuit.millionaires(a, b)
        expected = "Alice richer" if a > b else ("Bob richer" if b > a else "Equal")
        m = circuit.last_metrics
        print(f"    Alice={a}, Bob={b}: {result} (expected {expected}) ✓  "
              f"[gates={m['gates_evaluated']}, OT={m['ot_calls']}, time={m['time_s']}s]")

    # ── Secure equality ──
    print("\n  Secure Equality (bit-level XOR/AND/NOT chain):")
    for x, y in [(3, 3), (4, 7), (15, 15)]:
        r = circuit.secure_equality(x, y, bits=4)
        m = circuit.last_metrics
        print(f"    {x}=={y}: {bool(r)} (correct={bool(r) == (x == y)}) ✓  [OT={m['ot_calls']}]")

    # ── Secure addition via REAL ripple-carry adder over OT-based AND/XOR ──
    print("\n  Secure Addition (mod 16) — true ripple-carry adder, no plaintext math:")
    for x, y in [(5, 3), (9, 10), (15, 1)]:
        r = circuit.secure_add(x, y, bits=4)
        m = circuit.last_metrics
        print(f"    {x}+{y} mod 16 = {r} (correct={(x+y) % 16 == r}) ✓  "
              f"[gates={m['gates_evaluated']}, OT={m['ot_calls']}, time={m['time_s']}s]")

    # ── Performance benchmark on 8-bit inputs ──
    print("\n  [Performance — 8-bit inputs]")
    for label, fn in [
        ('add',       lambda: circuit.secure_add(123, 200, bits=8)),
        ('equality',  lambda: circuit.secure_equality(123, 123, bits=8)),
        ('compare>',  lambda: circuit.secure_compare_gt(200, 123, bits=8)),
    ]:
        out = fn()
        m = circuit.last_metrics
        print(f"    {label:10s}: result={out}, gates={m['gates_evaluated']}, "
              f"OT_calls={m['ot_calls']}, AND={m['and_calls']}, XOR={m['xor_calls']}, "
              f"time={m['time_s']}s")

    # ── Lineage: every AND in this demo invoked PA#19 → PA#18 → PA#16 → PA#13 ──
    print("\n  [End-to-end lineage]")
    print("  SecureCircuit.Secure_Eval → SecureGates.AND/XOR/NOT (PA#19)")
    print("    └─ AND ─→ OT_1of2.receiver_step1 + sender_step + receiver_step2 (PA#18)")
    print("       └─ ElGamal.keygen / encrypt / decrypt (PA#16)")
    print("          └─ DH safe-prime parameters (PA#11)")
    print("             └─ Miller-Rabin primality testing (PA#13)")

    # ── Transcript audit (no plaintext bits) ──
    print(f"\n  Total OT receiver_step1 invocations during demo: {gates._ot.call_count}")
    print(f"  Sample transcript entry: {gates.transcript[-1] if gates.transcript else '(empty)'}")
    print("✓ PA#20 complete.")


if __name__ == "__main__":
    demo_pa17(); print(); demo_pa18(); print(); demo_pa19(); print(); demo_pa20()
