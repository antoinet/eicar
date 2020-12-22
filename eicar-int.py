#!/usr/bin/env python

import sys
import r2pipe

r2 = r2pipe.open()
num = int(sys.argv[1])
r = r2.cmdj("arj")
ah = r["ax"] >> 8
if num == 0x20:
    print("[INT 20h] Terminate program")
elif num == 0x21:
    if ah == 0x09:
        start = r["dx"]
        r2.cmd("s %d" % start)
        r2.cmd("s/ $")
        end = int(r2.cmd("s"), 16)
        length = end - start
        print("[INT 21h, ah=%02xh] start: %04xh, length: %d" % (ah, start, length))
        print(r2.cmd("ps %d @ %d" % (length, start)))
    else:
        print("[unhandled INT 21h, ah=%02xh]" % ah)
else:
    print("[unhandled INT %02xh]" % num)

