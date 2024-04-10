#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mercury.picoctf.net --port 36981 otp.py
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'otp.py'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'mercury.picoctf.net'
port = int(args.PORT or 36981)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

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

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
io.recvuntil("This is the encrypted flag!\n")
encrypted_flag = str(io.recvline(), "ascii").strip()
print("encrypted:",encrypted_flag)

flag_len = len(encrypted_flag)//2

reset_key = "?"*(50000-flag_len)
io.sendlineafter("What data would you like to encrypt? ",reset_key)

dummy_flag = "_"*flag_len
io.sendlineafter("What data would you like to encrypt? ",dummy_flag)

io.recvuntil("Here ya go!\n")
encrypted_dummy = str(io.recvline(), "ascii").strip()

def xor_list_str(a, b):
    # `a` is a list and `b` is a string
    return ''.join(list(map(lambda p, k: chr(p ^ ord(k)), a, b)))

def hex_to_dec_list(input_hex):
    # Convert a hex string to a decimal array.
    # Split the hex string into groups of 2.
    input_hex = [input_hex[i:i+2] for i in range(0, len(input_hex), 2)]
    # Convert each two hex characters to decimal.
    output = [int(x, 16) for x in input_hex]
    return output

encrypted_dummy = hex_to_dec_list(encrypted_dummy)
key = xor_list_str(encrypted_dummy, dummy_flag)
# print("key %s" % key)
print(xor_list_str(hex_to_dec_list(encrypted_flag), key))

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
