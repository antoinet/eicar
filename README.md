# EICAR Test File

`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

## Context
 * [European Institute for Computer Antivirus Research](https://www.eicar.org/?page_id=3950)
 * 68 bytes text file that is a legitimate executable COM file that can run on x86 MS Windows (except for 64-bit systems due 16-bit limitations).
 * When executed, it will print "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" and then stop.
 * Contains ASCII printable characters, uppercase letters and special characters

## Analysis with Radare2
 * COM files entry point is fixed at 0100h: `$ r2 -m 0x100 eicar.txt`
 * Look at file information with `i`, see the length is 0x44 (68 bytes)
 * Disassemble with `> pD`, it doesn't make any sense since...
 * switch to 16 bit: `> e asm.bits=16` and repeat: `> pD`, now it looks better
 * set two labels:
   * `> f eicarstr @ 0x011c` to denote the string
   * `> f end @ 0x0140` to denote the jump target
 * interpret the string type: `Cs (end-eicarstr) @ eicarstr`
 * initialize ESIL:
   * `e io.cache=true`
   * `> aeim 0x0200 0xff stack`
 * change to visual mode: `V` and switch to debug view: `pp`
 * step trough code, until self-modifying code `> aesu 0x0114`
 * step and watch how code is modified from garbage to `int 0x21`/AH=09h
 * install ESIL interrupt handler: `e cmd.esil.intr=#!pipe python eicar-int.py`
 * [DOS API](https://en.wikipedia.org/wiki/DOS_API)

## r2 script
```
$ r2 -qi eicar.r2 -
```

