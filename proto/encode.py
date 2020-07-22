#!/usr/bin/env python3


import sys

if len(sys.argv) < 2:
    print("usage: %s prefix_bits number" % sys.argv[0])
    sys.exit(1)

N = int(sys.argv[1])

if '0x' in sys.argv[2]:
    I = int(sys.argv[2], 16)
    print("%s" % I)
else:
    I = int(sys.argv[2])


def encode(N, I):
    r = []
    if I < 2**N - 1:
        # encode I on N bits
        r.append(I)
    else:
        r.append(2**N - 1)
        I -= (2**N - 1)
        while I >= 128:
            r.append(I % 128 + 128)
            I = I // 128
        r.append(I)

    return r
        

print(', '.join([ hex(x) for x in encode(N, I)]))
print('\n'.join([ '%10s' % bin(x)[2:] for x in encode(N, I)]))
