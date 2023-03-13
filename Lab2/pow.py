#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break;
    print(time.time(), "done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))

def solve_challenge(r):
    print()
    r.recv()
    receive = r.recv().decode()
    time = int(receive.split("complete the ")[1].split(" challenges in")[0])
    time -= 1
    equ = receive.split(":")[1].split("=")[0]
    print("Equation:", equ)
    answer = eval(equ)
    print("Answer:", answer)
    print("------")
    r.sendline(base64.b64encode(answer.to_bytes((answer.bit_length() + 7) // 8, 'little')))
    while time:
        receive = r.recv().decode()
        print("Receive:", receive)
        equ = receive.split(":")[1].split("=")[0]
        print("Equation:", equ)
        answer = eval(equ)
        print("Answer:", answer)
        print("------")
        r.sendline(base64.b64encode(answer.to_bytes((answer.bit_length() + 7) // 8, 'little')))
        time -= 1
    
    receive = r.recv().decode()
    receive = r.recv().decode()
    print(receive)

if __name__ == '__main__':
    #r = remote('localhost', 10330);
    r = remote('up23.zoolab.org', 10363)
    solve_pow(r)
    # r.interactive()
    solve_challenge(r)
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
