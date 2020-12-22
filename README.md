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
            ;-- ip:
            0000:0100      58             pop ax
            0000:0101      354f21         xor ax, 0x214f
            0000:0104      50             push ax
            0000:0105      254041         and ax, 0x4140
            0000:0108      50             push ax
            0000:0109      5b             pop bx
            0000:010a      345c           xor al, 0x5c
            0000:010c      50             push ax
            0000:010d      5a             pop dx
            0000:010e      58             pop ax
            0000:010f      353428         xor ax, 0x2834
            0000:0112      50             push ax
            0000:0113      5e             pop si
            0000:0114      2937           sub word [bx], si
            0000:0116      43             inc bx
            0000:0117      43             inc bx
            0000:0118      2937           sub word [bx], si
            0000:011a      7d24           jge 0x140
            0000:011c     .string "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$" ; len=36
            0000:0140      48             dec ax
            0000:0141      2b482a         sub cx, word [bx + si + 0x2a]
Searching 1 byte in [0x11d-0x200]
[INT 21h, ah=09h] start: 011ch, length: 35
EICAR-STANDARD-ANTIVIRUS-TEST-FILE!

[INT 20h] Terminate program
[unhandled INT 21h, ah=28h]
[INT 20h] Terminate program
            0000:0100      58             pop ax                       ; ax=0x0 ; sp=0x283
            0000:0101      354f21         xor ax, 0x214f               ; ax=0x214f ; zf=0x0 ; pf=0x0 ; sf=0x0 ; cf=0x0 ; of=0x0
            0000:0104      50             push ax                      ; sp=0x281 sp
            0000:0105      254041         and ax, 0x4140               ; ax=0x140 -> 0x20cd21cd ; zf=0x0 ; pf=0x0 ; sf=0x0 ; cf=0x0 ; of=0x0
            0000:0108      50             push ax                      ; sp=0x27f "{\t" bp
            0000:0109      5b             pop bx                       ; bx=0x97b si ; sp=0x281 sp
            0000:010a      345c           xor al, 0x5c                 ; al=0x1c ; zf=0x0 ; pf=0x0 ; sf=0x0 ; cf=0x0 ; of=0x0
            0000:010c      50             push ax                      ; sp=0x27f "{\t" bp
            0000:010d      5a             pop dx                       ; dx=0x97b si ; sp=0x281 sp
            0000:010e      58             pop ax                       ; ax=0x0 ; sp=0x283
            0000:010f      353428         xor ax, 0x2834               ; ax=0x2834 ; zf=0x0 ; pf=0x0 ; sf=0x0 ; cf=0x0 ; of=0x0
            0000:0112      50             push ax                      ; sp=0x281 sp
            0000:0113      5e             pop si                       ; si=0x0 ; sp=0x283
            0000:0114      2937           sub word [bx], si            ; of=0x0 ; sf=0x1 flags ; zf=0x0 ; pf=0x1 flags ; cf=0x0
            0000:0116      43             inc bx                       ; bx=0x97c ; of=0x0 ; sf=0x0 ; zf=0x0 ; pf=0x0
            0000:0117      43             inc bx                       ; bx=0x97d ; of=0x0 ; sf=0x0 ; zf=0x0 ; pf=0x1 flags
            0000:0118      2937           sub word [bx], si            ; of=0x0 ; sf=0x1 flags ; zf=0x0 ; pf=0x1 flags ; cf=0x0
            0000:011a      7d24           jge 0x140                    ; unlikely
            ;-- dx:
            0000:011c     .string "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$" ; len=36
            0000:0140      cd21           int 0x21                     ; 40 = unknown ()
            ;-- bx:
            0000:0142      cd20           int 0x20                     ; 40 = unknown ()
```

