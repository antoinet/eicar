o eicar.txt 0x100
e asm.arch=x86
e asm.bits=16
e io.cache=true
"e cmd.esil.intr=#!pipe python eicar-int.py"
s 0x100
f eicarstr @ 0x011c
f end @ 0x0140
Cs (end-eicarstr) @ eicarstr
aeim 0x200 0xff stack
pD 0x44
e asm.emu=true
aec
s 0x100
pD 0x44
