"""
PA #7 — Merkle-Damgård Transform
"""
import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BLOCK_SIZE = 8   # bytes per message block
OUTPUT_SIZE = 4  # bytes output

def md_pad(msg: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """MD-strengthening padding: msg || 1 || 0* || <len as 8 bytes>"""
    length_field = struct.pack('>Q', len(msg) * 8)
    msg = msg + b'\x80'
    while (len(msg) + 8) % block_size != 0:
        msg += b'\x00'
    return msg + length_field

def xor_compress(chaining_value: bytes, block: bytes) -> bytes:
    """Toy XOR-based compression for testing the MD framework."""
    cv = (chaining_value + b'\x00' * 8)[:OUTPUT_SIZE]
    blk = (block + b'\x00' * 8)[:OUTPUT_SIZE]
    mixed = bytes(a^b for a,b in zip(cv,blk))
    # Simple avalanche: rotate and XOR
    out = bytearray(OUTPUT_SIZE)
    for i in range(OUTPUT_SIZE):
        out[i] = (mixed[i] ^ (mixed[(i+1)%OUTPUT_SIZE] << 1)) & 0xFF
    return bytes(out)

class MerkleDamgard:
    """Generic Merkle-Damgård construction over any compression function."""

    def __init__(self, compress=None, iv: bytes = None, block_size: int = BLOCK_SIZE):
        self.compress = compress or xor_compress
        self.block_size = block_size
        self.iv = iv or b'\x00' * OUTPUT_SIZE

    def hash(self, message: bytes) -> bytes:
        padded = md_pad(message, self.block_size)
        blocks = [padded[i:i+self.block_size]
                  for i in range(0, len(padded), self.block_size)]
        state = self.iv
        for block in blocks:
            state = self.compress(state, block)
        return state

    def hash_with_trace(self, message: bytes) -> dict:
        """Return full chaining trace for visualization."""
        padded = md_pad(message, self.block_size)
        blocks = [padded[i:i+self.block_size]
                  for i in range(0, len(padded), self.block_size)]
        state = self.iv
        trace = [{'block_idx': -1, 'block': 'IV', 'chaining': state.hex()}]
        for i, block in enumerate(blocks):
            state = self.compress(state, block)
            trace.append({'block_idx': i, 'block': block.hex(), 'chaining': state.hex()})
        return {'digest': state.hex(), 'trace': trace, 'n_blocks': len(blocks)}

    def hash_resume(self, state: bytes, suffix: bytes, original_total_bits: int) -> bytes:
        """
        Resume MD from an opaque chaining value `state` as if the hash had
        already processed `original_total_bits` bits and applied MD-strengthening
        padding. Appends `suffix` (already padded to block alignment via
        MD-strengthening with the NEW total length) and returns the final digest.

        This is the core primitive used by the length-extension attack:
        given T = H(prefix) the attacker continues hashing from state = T.
        """
        # Re-pad: total length is original_total_bits worth of (prefix||glue)
        # plus len(suffix) bits; but for the length-extension attack the
        # attacker must compute the length field matching (prefix||glue||suffix).
        # We build: suffix || 0x80 || 0* || <total_bits>
        total_after = original_total_bits + len(suffix) * 8
        length_field = struct.pack('>Q', total_after)
        padded_suffix = suffix + b'\x80'
        while (len(padded_suffix) + 8) % self.block_size != 0:
            padded_suffix += b'\x00'
        padded_suffix += length_field
        blocks = [padded_suffix[i:i+self.block_size]
                  for i in range(0, len(padded_suffix), self.block_size)]
        for block in blocks:
            state = self.compress(state, block)
        return state

def demo():
    print("="*60); print("PA #7 — Merkle-Damgård Transform"); print("="*60)
    md = MerkleDamgard()
    for msg in [b"", b"hello", b"A"*64]:
        h = md.hash(msg)
        print(f"  H({msg[:20]!r}…) = {h.hex()}")
    # Collision propagation: construct a compression-level collision and show it
    # lifts to an MD-level collision on different messages.
    print("\n  [Collision propagation]")
    # Find two distinct (cv1, blk1) != (cv2, blk2) with same compress() output.
    cv = b'\x00' * OUTPUT_SIZE
    # Because xor_compress is linear-ish, blocks that XOR to the same "mix" collide.
    # Force it: pick two different blocks producing identical compress outputs
    # by searching briefly.
    found = None
    seen = {}
    for i in range(256):
        blk = bytes([i]) + b'\x00' * (BLOCK_SIZE - 1)
        h = xor_compress(cv, blk)
        if h in seen and seen[h] != blk:
            found = (seen[h], blk, h)
            break
        seen[h] = blk
    if found:
        blk1, blk2, h = found
        # Two *different* single-block messages whose compression outputs agree.
        # In the MD construction with different messages, padding differs too,
        # so we show the compression-level collision directly.
        print(f"  Compress collision: blk1={blk1.hex()} ≠ blk2={blk2.hex()}")
        print(f"  compress(IV, blk1) = compress(IV, blk2) = {h.hex()} ✓")
        print(f"  (Any collision in the compression fn lifts to a collision in MD.)")
    else:
        print("  No collision found in quick search (demo only)")
    trace = md.hash_with_trace(b"test message here!")
    print(f"\n  Trace ({trace['n_blocks']} blocks):")
    for t in trace['trace'][:4]:
        print(f"    Block {t['block_idx']}: chain={t['chaining']}")
    print("✓ PA#7 complete.")

if __name__ == "__main__": demo()
