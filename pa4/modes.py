"""PA #4 — Modes of Operation (CBC / OFB / CTR)"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa2.prf_ggm import AES_PRF

BLOCK = 16
def _xor(a,b): return bytes(x^y for x,y in zip(a,b))
def _pad(d,bs=BLOCK): n=bs-len(d)%bs; return d+bytes([n]*n)
def _unpad(d): n=d[-1]; return d[:-n]
def _int_block(n): return n.to_bytes(BLOCK,'big')
def _block_int(b): return int.from_bytes(b,'big')
def _prf(key,block): return AES_PRF.evaluate(key,block)

class CBC:
    def encrypt(self,key,iv,msg):
        p=_pad(msg); prev=iv; ct=b''
        for i in range(len(p)//BLOCK):
            blk=p[i*BLOCK:(i+1)*BLOCK]; cb=_xor(_prf(key,prev),blk); ct+=cb; prev=cb
        return ct
    def decrypt(self,key,iv,ct):
        prev=iv; pt=b''
        for i in range(len(ct)//BLOCK):
            blk=ct[i*BLOCK:(i+1)*BLOCK]; pt+=_xor(_prf(key,prev),blk); prev=blk
        return _unpad(pt)

class OFB:
    def _ks(self,key,iv,n_blocks):
        ks=b''; s=iv
        for _ in range(n_blocks): s=_prf(key,s); ks+=s
        return ks
    def encrypt(self,key,iv,msg):
        p=_pad(msg); ks=self._ks(key,iv,len(p)//BLOCK)
        return _xor(p,ks[:len(p)])
    def decrypt(self,key,iv,ct):
        # OFB: keystream same in both directions, but ct already unpadded
        # We need the padded length to regenerate correct keystream
        # Store padded length in last block implicitly via pad bytes
        n_blocks=(len(ct)+BLOCK-1)//BLOCK
        ks=self._ks(key,iv,n_blocks)
        return _unpad(_xor((ct+b'\x00'*BLOCK)[:n_blocks*BLOCK], ks[:n_blocks*BLOCK])[:n_blocks*BLOCK])

class CTR:
    def encrypt(self,key,msg):
        r=os.urandom(BLOCK); p=_pad(msg); ct=b''
        for i in range(len(p)//BLOCK):
            ctr=_int_block((_block_int(r)+i)%(2**128)); ct+=_xor(_prf(key,ctr),p[i*BLOCK:(i+1)*BLOCK])
        return r,ct
    def decrypt(self,key,r,ct):
        pt=b''
        for i in range(len(ct)//BLOCK):
            ctr=_int_block((_block_int(r)+i)%(2**128)); pt+=_xor(_prf(key,ctr),ct[i*BLOCK:(i+1)*BLOCK])
        return _unpad(pt)

class Modes:
    def __init__(self): self.cbc=CBC(); self.ofb=OFB(); self.ctr=CTR()
    def encrypt(self,mode,key,msg):
        if mode=='CBC': iv=os.urandom(BLOCK); return {'iv':iv,'ct':self.cbc.encrypt(key,iv,msg),'mode':'CBC'}
        elif mode=='OFB': iv=os.urandom(BLOCK); return {'iv':iv,'ct':self.ofb.encrypt(key,iv,msg),'mode':'OFB'}
        elif mode=='CTR': r,ct=self.ctr.encrypt(key,msg); return {'r':r,'ct':ct,'mode':'CTR'}
    def decrypt(self,mode,key,data):
        if mode=='CBC': return self.cbc.decrypt(key,data['iv'],data['ct'])
        elif mode=='OFB': return self.ofb.decrypt(key,data['iv'],data['ct'])
        elif mode=='CTR': return self.ctr.decrypt(key,data['r'],data['ct'])

def demo():
    print("="*60); print("PA #4 — Modes of Operation"); print("="*60)
    m=Modes(); key=os.urandom(16)
    for mode in ['CBC','OFB','CTR']:
        for tag,msg in [('short',b"Hi!"),('exact',b"ExactOneBlock!!!"),('multi',b"Multi block message here!")]:
            enc=m.encrypt(mode,key,msg); dec=m.decrypt(mode,key,enc)
            print(f"  {mode} [{tag}]: {'✓' if msg==dec else '✗ '+repr(dec)}")
    print("✓ PA#4 complete.")

if __name__ == "__main__": demo()
