"""Independent-trial diagnostic derived from the Apache-2.0 promoted package.
Source: Layr-Labs/hash-smash, commit55dfae1cfb429015a293db48c7c9f88f566641e2,
submission40087647-1a84-4a2b-bb18-5b8edf0edefa, experiments/frontline.py.
Original authors/contributors are credited in the source proof Section16.
Selected constructor/forward-arithmetic definitions are retained; the symbolic
interpreter, independent sampling and bounded diagnostic wrapper are new.
The Apache-2.0 grant for promoted submissions is in production Terms Section5.
This source runs only in the organizer's isolated networkless Python executor.
"""
import hashlib
import json
import struct
import sys

M = 0xFFFFFFFF
IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
K = (IV[2] + IV[6]) & M
LEN_A, LEN_B = 55, 63
X3, X7, X11, X15 = 0x29D4FA98, 0xBEE3AF28, 0x44036000, 0x40C58500
W4, W13 = 0x97475638, 0x0007C006
W4B = (((W4 + K) & M) ^ LEN_A ^ LEN_B) - K & M
DELTA5 = (W4 - W4B) & M
ETA, EPS, MU, BETA = 0x830303CF, 0x6E21BE55, 0x9AED22BD, 0x18B0E098
FLAGS, ROOT_FLAGS = 3, 11
PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
GCALLS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
          (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))
REP_BATCHES, TRIAL_REPS = 2341, 5
T2_EVERY = 1


def ror(v, n):
    n &= 31
    return ((v >> n) | (v << (32 - n))) & M if n else v


def rol(v, n):
    return ror(v, 32 - (n & 31))


def bit(x, i):
    return x >> i & 1


def maj(a, b, c):
    return (a & b) | (a & c) | (b & c)


def g(a, b, c, d, x, y):
    a = (a + b + x) & M; d = ror(d ^ a, 16); c = (c + d) & M; b = ror(b ^ c, 12)
    a = (a + b + y) & M; d = ror(d ^ a, 8); c = (c + d) & M; b = ror(b ^ c, 7)
    return a, b, c, d


Y3, Y7, Y11, Y15 = g(X3, X7, X11, X15, W4, W13)
Y3B, Y7B, Y11B, Y15B = g(X3, X7, X11, X15, W4B, W13)
DY3, DY11 = (Y3B - Y3) & M, (Y11B - Y11) & M
K2A = (K + W4) & M
K2D = ror(K2A ^ LEN_A, 16)
K2C = (IV[2] + K2D) & M
K2B = ror(IV[6] ^ K2C, 12)
assert (Y7, Y15) == (Y7B, Y15B) and (Y3, DY3, Y11, DY11) == (0x8127C181, 0xFDB77CFD, 0x7AF77F38, 0x0A08818B)
assert DELTA5 == (-8) & M and ror(ETA ^ EPS, 8) == MU

def Sum(*t):
    return ("sum", t)


def Neg(x):
    return ("neg", x)


def X(a, b):
    return ("xor", a, b)


def R(a, r):
    return ("ror", a, r)


def L(a, r):
    return ("ror", a, 32 - r)


LINES = [
    ("X2", Sum("D2.a1", "D2.b1", W13)), ("X8", X(rol(X7, 7), "D2.b1")), ("C0.c1", Sum("X8", "C0.d1")),
    ("K3.a1", Sum((IV[3] + IV[7]) & M, "w6")), ("K3.d1", R(X("K3.a1", "fl"), 16)), ("K3.c1", Sum(IV[3], "K3.d1")),
    ("S15", Sum("S11", Neg("K3.c1"))), ("S3", X(L("S15", 8), "K3.d1")), ("K3.b1", R(X(IV[7], "K3.c1"), 12)),
    ("D3.a1", Sum("S3", "S4")), ("S7", R(X("K3.b1", "S11"), 7)), ("D3.b1", Sum(X3, Neg("D3.a1"))),
    ("D2.c1", X(L("D2.b1", 12), "S7")), ("D3.c1", X(L("D3.b1", 12), "S4")), ("X4", R(X("D3.b1", "X9"), 7)),
    ("X13", Sum("X8", Neg("D2.c1"))), ("X14", Sum("X9", Neg("D3.c1"))), ("C0.b1", R(X("X4", "C0.c1"), 12)),
    ("D2.d1", X(L("X13", 8), "X2")), ("D3.d1", X(L("X14", 8), X3)), ("Y8", X(L("Y4", 7), "C0.b1")),
    ("S13", X(L("D2.d1", 16), "D2.a1")), ("S9", Sum("D3.c1", Neg("D3.d1"))), ("Y12", Sum("Y8", Neg("C0.c1"))),
    ("K1.c1", Sum("S9", Neg("S13"))), ("Y0", X(L("Y12", 8), "C0.d1")), ("K1.d1", Sum("K1.c1", Neg(IV[1]))),
    ("C0.a1", Sum("Y0", Neg("C0.b1"), Neg("w6"))), ("K1.a1", L("K1.d1", 16)),
    ("w2", Sum("K1.a1", Neg(IV[1]), Neg(IV[5]))), ("X0", Sum("C0.a1", Neg("X4"), Neg("w2"))),
    ("S14", X(L("D3.d1", 16), "D3.a1")), ("K1.b1", R(X(IV[5], "K1.c1"), 12)), ("S10", Sum(K2C, "S14")),
    ("D0.d1", X(rol(X15, 8), "X0")), ("S5", R(X("K1.b1", "S9"), 7)), ("D0.c1", Sum("S10", "D0.d1")),
    ("D0.b1", R(X("S5", "D0.c1"), 12)), ("X10", Sum("D0.c1", X15)), ("X5", R(X("D0.b1", "X10"), 7)),
    ("S1", X(L("S13", 8), "K1.d1")), ("w3", Sum("S1", Neg("K1.a1"), Neg("K1.b1"))),
    ("X12", X(L("C0.d1", 16), "C0.a1")), ("D1.c1", Sum(X11, Neg("X12"))), ("D1.d1", Sum("D1.c1", Neg("S11"))),
    ("S8", Sum("D2.c1", Neg("D2.d1"))), ("K0.b1", X(L("S4", 7), "S8")), ("S2", X(L("S14", 8), K2D)),
    ("S6", R(X(K2B, "S10"), 7)), ("X1", X(L("X12", 8), "D1.d1")), ("K0.c1", X(L("K0.b1", 12), IV[4])),
    ("D1.b1", R(X("S6", "D1.c1"), 12)), ("C1.a1", Sum("X1", "X5", "w3")), ("S12", Sum("S8", Neg("K0.c1"))),
    ("w7", Sum("S3", Neg("K3.a1"), Neg("K3.b1"))), ("X6", R(X("D1.b1", X11), 7)),
    ("C1.d1", R(X("X13", "C1.a1"), 16)), ("D1.a1", X(L("D1.d1", 16), "S12")), ("C1.c1", Sum("X9", "C1.d1")),
    ("C2.a1", Sum("X2", "X6", "w7")), ("w10", Sum("D1.a1", Neg("S1"), Neg("S6"))),
    ("C1.b1", R(X("X5", "C1.c1"), 12)), ("C2.d1", R(X("X14", "C2.a1"), 16)),
    ("w12", Sum("D2.a1", Neg("S2"), Neg("S7"))), ("Y1", Sum("C1.a1", "C1.b1", "w10")),
    ("C2.c1", Sum("X10", "C2.d1")), ("Y13", R(X("C1.d1", "Y1"), 8)), ("C2.b1", R(X("X6", "C2.c1"), 12)),
    ("K0.d1", Sum("K0.c1", Neg(IV[0]))), ("Y9", Sum("C1.c1", "Y13")), ("S0", X(L("S12", 8), "K0.d1")),
    ("D0.a1", X(L("D0.d1", 16), "S15")), ("w8", Sum("D0.a1", Neg("S0"), Neg("S5"))),
    ("w5", Sum("S2", Neg(K2A), Neg(K2B))), ("w9", Sum("X0", Neg("D0.a1"), Neg("D0.b1"))),
    ("w11", Sum("X1", Neg("D1.a1"), Neg("D1.b1"))), ("Y5", R(X("C1.b1", "Y9"), 7)),
]
def compress2(msg, t, flags):
    n = len(msg)
    w = list(struct.unpack("<16I", msg + bytes(64 - n)))
    v = list(IV) + list(IV[:4]) + [t & M, t >> 32, n, flags]
    s, yst = w, None
    for r in range(2):
        for i, (a, b, c, d) in enumerate(GCALLS):
            if r == 1 and i == 4:
                yst = list(v)
            v[a], v[b], v[c], v[d] = g(v[a], v[b], v[c], v[d], s[2 * i], s[2 * i + 1])
        s = [s[p] for p in PERM]
    return w, [v[i] ^ v[i + 8] for i in range(8)], yst


def c1_of(v, h):
    y6 = ror((((rol(h, 16) ^ v["e1"]) + v["C2_c1"]) & M) ^ v["C2_b1"], 7)
    return (Y11 + ror(((y6 + v["Y1"] + v["w12"]) & M) ^ v["Y12"], 16)) & M


def c1_t0(v):
    w0 = (rol(v["K0_d1"], 16) - IV[0] - IV[4]) & M
    y14 = ror(((w0 + v["C2_a1"] + v["C2_b1"]) & M) ^ v["C2_d1"], 8)
    return c1_of(v, ror(y14 ^ v["e1"], 16))


def step_ct(v, c1):
    u = dict(v)
    u["E1_a1"] = rol((c1 - Y11) & M, 16) ^ u["Y12"]
    u["Y6"] = (u["E1_a1"] - u["Y1"] - u["w12"]) & M
    u["Y10"] = rol(u["Y6"], 7) ^ u["C2_b1"]
    u["Y14"] = (u["Y10"] - u["C2_c1"]) & M
    u["E1_b1"] = ror(u["Y6"] ^ c1, 12)
    u["Y2"] = rol(u["Y14"], 8) ^ u["C2_d1"]
    u["E3_h1"] = ror(u["Y14"] ^ u["e1"], 16)
    u["w0"] = (u["Y2"] - u["C2_a1"] - u["C2_b1"]) & M
    u["K0_a1"] = (IV[0] + IV[4] + u["w0"]) & M
    u["t"] = rol(u["K0_d1"], 16) ^ u["K0_a1"]
    u["w1"] = (u["S0"] - u["K0_a1"] - u["K0_b1"]) & M
    w = [u.get("w%d" % i, 0) for i in range(16)]
    w[4], w[13] = W4, W13
    b = list(w)
    b[4], b[5] = W4B, (w[5] + DELTA5) & M
    pa, pb = struct.pack("<16I", *w), struct.pack("<16I", *b)
    assert not any(pa[LEN_A:]) and not any(pb[LEN_B:])
    u["A"], u["B"], u["c1"] = pa[:LEN_A], pb[:LEN_B], c1
    return u



CLASS_MASK, CLASS_VALUE = 0x03CF8303, 0x030C0303
QSTAR_MASK, QSTAR_VALUE = 0x0E09818B, 0x02008000
OUTER_WORDS = ('C0_d1','D2_a1','D2_b1','S11','S4','X9','w6')

def evaluate(expr, values):
    if isinstance(expr,int):
        return expr & M
    if isinstance(expr,str):
        return values[expr.replace('.','_')]
    tag=expr[0]
    if tag=='sum':
        return sum(evaluate(x,values) for x in expr[1]) & M
    if tag=='neg':
        return -evaluate(expr[1],values) & M
    if tag=='xor':
        return evaluate(expr[1],values) ^ evaluate(expr[2],values)
    if tag=='ror':
        return ror(evaluate(expr[1],values),expr[2])
    raise ValueError('invalid static constructor expression')

def co_full(outer,y,flags):
    values=dict(zip(OUTER_WORDS,outer))
    values.update(Y4=y,fl=flags)
    for name,expr in LINES:
        values[name.replace('.','_')]=evaluate(expr,values)
    values['e1']=(Y3+y)&M
    return values

def member(index):
    free=[i for i in range(32) if not (CLASS_MASK>>i&1)]
    e=CLASS_VALUE | sum((index>>j&1)<<position for j,position in enumerate(free))
    return (e-Y3)&M

def beta_of(words,state):
    a=(state[1]+state[6]+words[12])&M
    d=ror(state[12]^a,16)
    c=(state[11]+d)&M
    return ror(state[6]^c,12)

def main():
    request=json.load(sys.stdin)
    trials=[]
    for tr in request['trials']:
        material=hashlib.shake_256(b'independent-counter-v1'+bytes.fromhex(tr['seed'])).digest(64)
        U=int.from_bytes(material[:32],'little');V=int.from_bytes(material[32:],'little')
        outer=[U>>(32*i)&M for i in range(7)]
        y=member(U>>224&((1<<19)-1))
        c=QSTAR_VALUE | ((V&M)&(~QSTAR_MASK&M))
        chart=co_full(outer,y,3)
        counter=step_ct(chart,c)
        wa,ca,ya=compress2(counter['A'],counter['t'],3)
        wb,cb,yb=compress2(counter['B'],counter['t'],3)
        half=int(all(ca[i]==cb[i] for i in (0,2,5,7)))
        beta=int((beta_of(wa,ya)^beta_of(wb,yb))==BETA)
        root_chart=co_full(outer,y,11)
        root=step_ct(root_chart,c1_t0(root_chart))
        if root['t']!=0:
            raise ValueError('root-counter cancellation failed')
        trials.append({'trial':tr['trial'],'message_a_hex':root['A'].hex(),
                       'message_b_hex':root['B'].hex(),'observations':{
                           'counter_half_equal':half,'prescribed_beta_equal':beta,
                           'counter_nonzero':int(counter['t']!=0),
                           'counter_full_equal':int(ca==cb),
                           'root_counter_zero':int(root['t']==0),
                           'residual_low8_zero':int((ca[1]^cb[1])&255==0)}})
    json.dump({'schema_version':1,'trials':trials},sys.stdout,sort_keys=True,separators=(',',':'))

if __name__=='__main__':
    main()
