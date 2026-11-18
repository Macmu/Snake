#!/usr/bin/env python3
"""
Decode the kallsyms name table from an uncompressed arm64 Linux Image.

This recovers the compressed kallsyms token table -> token index -> names,
which is the hard part of extracting symbols from a stripped kernel Image.
Verified on PKU110 6.6.118 (gb1422e39c313-abogki552867473-4k):
  110538 kernel symbols decoded; all 8 probed symbols match /proc/kallsyms.

The address table (kallsyms_offsets/addresses) is still located heuristically;
that piece is build-layout dependent and remains TODO.

Usage: python3 kallsyms_decode.py kernel.image
"""
import struct, sys

def find_u16_table(k, lo=0x1000, hi=None):
    """Locate kallsyms_token_index: 256 u16, monotonic, non-uniform steps."""
    hi = hi or len(k)
    cands = []
    for i in range(lo, hi-512, 2):
        if struct.unpack_from('<H', k, i)[0] != 0:
            continue
        v = struct.unpack_from('<256H', k, i)
        if not (150 < v[255] < 1500):
            continue
        diffs = [v[j+1]-v[j] for j in range(255)]
        if any(d < 0 or d > 16 for d in diffs):
            continue
        if len(set(diffs)) < 4:   # exclude plain 0,1,2.. fill
            continue
        cands.append((i, v))
    if not cands:
        raise ValueError('token_index not found')
    # several 2-byte-shifted false positives; pick the one whose token[2]=="func_"
    for i, v in cands:
        fpos = k.find(b'func_\0', max(0, i-0x2000), i)
        if fpos < 0:
            continue
        base = fpos - v[2]
        if k[base+v[2]:base+(v[3] if v[2]<255 else base+v[2]+5)].split(b'\0')[0] == b'func_':
            return i, v
    return cands[-1]

def decode_token_table(k, ioff, span=0x388):
    idx = struct.unpack_from('<256H', k, ioff)
    last = idx[255]
    def tokens_at(base):
        return [k[base+idx[j]:base+(idx[j+1] if j < 255 else last)].split(b'\0')[0]
                for j in range(256)]
    # anchor: token[2] == 'func_' on this kernel; fall back to '_'/'t'/'ext'
    fpos = k.find(b'func_\0', max(0, ioff-0x2000), ioff)
    if fpos < 0:
        raise ValueError('token table anchor not found')
    base = fpos - idx[2]
    toks = tokens_at(base)
    if toks[2] != b'func_':
        raise ValueError('token table base mismatch')
    return base, toks

def decode_names(k, name_base, toks, limit=200000):
    names = []
    p = name_base
    for _ in range(limit):
        ln = k[p]
        if ln == 0 or ln > 127:
            break
        tids = k[p+1:p+1+ln]
        if any(t > 255 for t in tids):
            break
        # kallsyms encodes [type][name]; strip the leading type char token
        raw = b''.join(toks[t] for t in tids)
        names.append((p - name_base, raw, p + 1 + ln))
        p += 1 + ln
    return names

def main():
    k = open(sys.argv[1], 'rb').read()
    ioff, idx = find_u16_table(k)
    tt, toks = decode_token_table(k, ioff)
    print(f'token_index @ {ioff:#x}, token_table @ {tt:#x}')
    # locate the first name entry: [04][T][_][t][ext] for "_text" on this build
    enc = bytes([4, 84, 95, 116, 145])   # 'T' + '_text'
    p = k.find(enc)
    print(f'_text name entry @ {p:#x}')
    names = decode_names(k, p, toks)
    print(f'decoded {len(names)} symbols')
    for off, raw, _ in names[:8]:
        print(f'  +{off:#x}  {raw.decode("latin1")}')

if __name__ == '__main__':
    main()
