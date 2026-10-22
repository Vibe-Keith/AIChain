#!/usr/bin/env python3
"""
Build-time compiler: TinyLM inference kernel -> WebAssembly.

Python is used ONLY here, to generate files. Runtime is TS/JS/WASM.
No dependencies: emits the WASM binary format directly.

Output:
  dist/wasm/tinylm.wasm   kernel + weights (data segment)
  dist/wasm/tinylm.json   manifest (model id, layout, wasm hash)

Exports: memory, init(), step(tok), sample() -> tok,
         globals seed_ptr, hb_ptr, weights_len
Must stay bit-exact with src/model.ts (checked by `npm run test:wasm`).
"""
import hashlib, json, os

D, V, LO, HI = 128, 256, 32, 126
E_OFF = 0
WH_OFF = E_OFF + V * D
WO_OFF = WH_OFF + D * D
H_OFF = WO_OFF + D * V          # i32[D] hidden state
NX_OFF = H_OFF + D * 4          # i32[D] next state
HB_OFF = NX_OFF + D * 4         # u8[D]  state bytes for ticket hashing
SEED_OFF = HB_OFF + D           # u8[32] job seed
PAGES = 2
assert SEED_OFF + 32 <= PAGES * 65536

# ---------- weights (same PRNG as src/model.ts) ----------
def xorshift(seed):
    s = (seed & 0xFFFFFFFF) or 1
    def nxt():
        nonlocal s
        s ^= (s << 13) & 0xFFFFFFFF
        s ^= s >> 17
        s ^= (s << 5) & 0xFFFFFFFF
        return s
    return nxt

def weights():
    wr = xorshift(0xC0FFEE)
    fill = lambda n: bytes((((wr() % 16) - 8) & 0xFF) for _ in range(n))
    return fill(V * D) + fill(D * D) + fill(D * V)

# ---------- binary encoding ----------
def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | 0x80 if n else b)
        if not n: return bytes(out)

def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        done = (n == 0 and not b & 0x40) or (n == -1 and b & 0x40)
        out.append(b if done else b | 0x80)
        if done: return bytes(out)

vec = lambda items: uleb(len(items)) + b"".join(items)
blob = lambda b: uleb(len(b)) + b
section = lambda sid, payload: bytes([sid]) + blob(payload)
name = lambda s: blob(s.encode())

I32 = 0x7F
ADD, SUB, MUL, REM_U, AND, XOR, SHL, SHR_S, SHR_U = 0x6A, 0x6B, 0x6C, 0x70, 0x71, 0x73, 0x74, 0x75, 0x76
LT_S, GT_S, GE_S, SELECT = 0x48, 0x4A, 0x4E, 0x1B
RNG, SEED_PTR, HB_PTR, WEIGHTS_LEN = 0, 1, 2, 3  # global indices

class Asm:
    def __init__(self): self.b = bytearray()
    def op(self, *ops): self.b += bytes(ops)
    def const(self, v): self.b += b"\x41" + sleb(v)
    def get(self, l): self.b += b"\x20" + uleb(l)
    def set(self, l): self.b += b"\x21" + uleb(l)
    def gget(self, g): self.b += b"\x23" + uleb(g)
    def gset(self, g): self.b += b"\x24" + uleb(g)
    def load32(self): self.b += b"\x28\x02\x00"
    def load8s(self): self.b += b"\x2c\x00\x00"
    def load8u(self): self.b += b"\x2d\x00\x00"
    def store32(self): self.b += b"\x36\x02\x00"
    def store8(self): self.b += b"\x3a\x00\x00"
    def addr(self, idx_local, scale, base):  # push base + idx*scale
        self.get(idx_local)
        if scale != 1: self.const(scale); self.op(MUL)
        self.const(base); self.op(ADD)
    def for_range(self, var, start, end, body):
        self.const(start); self.set(var)
        self.op(0x02, 0x40); self.op(0x03, 0x40)            # block, loop
        self.get(var); self.const(end); self.op(GE_S)
        self.op(0x0D); self.b += uleb(1)                     # br_if exit
        body()
        self.get(var); self.const(1); self.op(ADD); self.set(var)
        self.op(0x0C); self.b += uleb(0)                     # br loop
        self.op(0x0B); self.op(0x0B)
    def func(self, n_locals):
        locs = vec([uleb(n_locals) + bytes([I32])]) if n_locals else uleb(0)
        body = locs + bytes(self.b) + b"\x0b"
        return blob(body)

# ---------- kernel functions ----------
def gen_init():  # () -> ()
    a = Asm(); i, t = 0, 1
    def body():
        a.addr(i, 4, H_OFF)
        a.get(i); a.const(31); a.op(AND); a.const(SEED_OFF); a.op(ADD); a.load8u()
        a.const(128); a.op(SUB); a.store32()
    a.for_range(i, 0, D, body)
    a.const(SEED_OFF); a.load32(); a.set(t)                 # rng = seed u32le || 1
    a.get(t); a.const(1); a.get(t); a.op(SELECT); a.gset(RNG)
    return a.func(2)

def gen_step():  # (tok) -> ()
    a = Asm(); TOK, i, j, acc, eo, ro, v = range(7)
    a.get(TOK); a.const(D); a.op(MUL); a.set(eo)
    def outer():
        a.get(eo); a.get(i); a.op(ADD); a.const(E_OFF); a.op(ADD); a.load8s()
        a.const(64); a.op(MUL); a.set(acc)
        a.get(i); a.const(D); a.op(MUL); a.set(ro)
        def inner():
            a.get(acc)
            a.get(ro); a.get(j); a.op(ADD); a.const(WH_OFF); a.op(ADD); a.load8s()
            a.addr(j, 4, H_OFF); a.load32()
            a.op(MUL); a.op(ADD); a.set(acc)
        a.for_range(j, 0, D, inner)
        a.get(acc); a.const(6); a.op(SHR_S); a.set(acc)
        a.const(127); a.get(acc); a.get(acc); a.const(127); a.op(GT_S); a.op(SELECT); a.set(acc)
        a.const(-127); a.get(acc); a.get(acc); a.const(-127); a.op(LT_S); a.op(SELECT); a.set(acc)
        a.addr(i, 4, NX_OFF); a.get(acc); a.store32()
    a.for_range(i, 0, D, outer)
    def copy():
        a.addr(i, 4, NX_OFF); a.load32(); a.set(v)
        a.addr(i, 4, H_OFF); a.get(v); a.store32()
        a.addr(i, 1, HB_OFF); a.get(v); a.store8()
    a.for_range(i, 0, D, copy)
    return a.func(6)

def gen_sample():  # () -> tok
    a = Asm(); v, i, l, best, tok, s = range(6)
    a.const(-(2 ** 31)); a.set(best); a.const(LO); a.set(tok)
    def per_v():
        a.gget(RNG); a.set(s)
        for sh, op in ((13, SHL), (17, SHR_U), (5, SHL)):
            a.get(s); a.get(s); a.const(sh); a.op(op); a.op(XOR); a.set(s)
        a.get(s); a.gset(RNG)
        a.get(s); a.const(4096); a.op(REM_U); a.set(l)
        def inner():
            a.get(l)
            a.get(i); a.const(V); a.op(MUL); a.get(v); a.op(ADD); a.const(WO_OFF); a.op(ADD); a.load8s()
            a.addr(i, 4, H_OFF); a.load32()
            a.op(MUL); a.op(ADD); a.set(l)
        a.for_range(i, 0, D, inner)
        a.get(l); a.get(best); a.op(GT_S)
        a.op(0x04, 0x40); a.get(l); a.set(best); a.get(v); a.set(tok); a.op(0x0B)
    a.for_range(v, LO, HI + 1, per_v)
    a.get(tok)
    return a.func(6)

# ---------- module ----------
def module(w):
    t_void = b"\x60" + vec([]) + vec([])
    t_i32_void = b"\x60" + vec([bytes([I32])]) + vec([])
    t_void_i32 = b"\x60" + vec([]) + vec([bytes([I32])])
    glob = lambda mut, val: bytes([I32, mut]) + b"\x41" + sleb(val) + b"\x0b"
    exp = lambda n, kind, idx: name(n) + bytes([kind]) + uleb(idx)
    return b"".join([
        b"\x00asm\x01\x00\x00\x00",
        section(1, vec([t_void, t_i32_void, t_void_i32])),
        section(3, vec([uleb(0), uleb(1), uleb(2)])),
        section(5, vec([b"\x00" + uleb(PAGES)])),
        section(6, vec([glob(1, 1), glob(0, SEED_OFF), glob(0, HB_OFF), glob(0, len(w))])),
        section(7, vec([exp("memory", 2, 0), exp("init", 0, 0), exp("step", 0, 1), exp("sample", 0, 2),
                        exp("seed_ptr", 3, SEED_PTR), exp("hb_ptr", 3, HB_PTR), exp("weights_len", 3, WEIGHTS_LEN)])),
        section(10, vec([gen_init(), gen_step(), gen_sample()])),
        section(11, vec([b"\x00\x41" + sleb(E_OFF) + b"\x0b" + blob(w)])),
    ])

if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "dist", "wasm"); os.makedirs(out, exist_ok=True)
    w = weights()
    wasm = module(w)
    with open(os.path.join(out, "tinylm.wasm"), "wb") as f: f.write(wasm)
    manifest = {
        "modelId": hashlib.sha256(w).hexdigest()[:16],
        "wasmSha256": hashlib.sha256(wasm).hexdigest(),
        "bytes": len(wasm),
        "dims": {"D": D, "V": V, "vocab": [LO, HI]},
        "layout": {"E": E_OFF, "Wh": WH_OFF, "Wo": WO_OFF, "h": H_OFF, "nx": NX_OFF, "hb": HB_OFF, "seed": SEED_OFF},
    }
    with open(os.path.join(out, "tinylm.json"), "w") as f: json.dump(manifest, f, indent=2)
    print(f"tinylm.wasm {len(wasm)} bytes, model {manifest['modelId']}")
