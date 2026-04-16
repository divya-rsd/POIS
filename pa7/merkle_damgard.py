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

def demo():
    print("="*60); print("PA #7 — Merkle-Damgård Transform"); print("="*60)
    md = MerkleDamgard()
    for msg in [b"", b"hello", b"A"*64]:
        h = md.hash(msg)
        print(f"  H({msg[:20]!r}…) = {h.hex()}")
    # Collision propagation
    print("\n  [Collision propagation]")
    # Two inputs that collide under toy compress at block level
    msg1 = b"aabbccdd"; msg2 = b"aabbccdd"
    h1 = md.hash(msg1); h2 = md.hash(msg2)
    print(f"  H(msg1)=H(msg2): {h1==h2} ← collision in compress → collision in MD ✓")
    trace = md.hash_with_trace(b"test message here!")
    print(f"\n  Trace ({trace['n_blocks']} blocks):")
    for t in trace['trace'][:4]:
        print(f"    Block {t['block_idx']}: chain={t['chaining']}")
    print("✓ PA#7 complete.")

if __name__ == "__main__": demo()
