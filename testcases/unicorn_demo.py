# -*- coding:utf-8 -*-  
from unicorn import *
from unicorn.x86_const import *
import os, signal

def read(name):
    with open(name, "rb") as fp:
        return fp.read()

insn_skip_list = [0x4004ef, 0x4004f6, 0x400502, 0x40054f, 0x400560]
def hook_code(mu, address, size, user_data):
    # print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

    if address in insn_skip_list:
        mu.reg_write(UC_X86_REG_RIP, address + size)
    
    # printf
    if address == 0x400502:
        str1 = mu.mem_read(mu.reg_read(UC_X86_REG_EDI), 13)
        print(str1.decode())

    # putc
    if address == 0x400560:
        str2 = mu.reg_read(UC_X86_REG_DIL)
        print(chr(str2))
        # Only for kill process. If you want to run this program, please delete this line of code
        os.kill(os.getpid(), signal.SIGABRT)

def unicorn_debug_block(uc, address, size, user_data):
    # Our tool uses "addr =" to track the data flow
    print("Basic Block: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))
    
# 1. initialize unicorn engine
mu = Uc(UC_ARCH_X86, UC_MODE_64)

# 2. memory
mu.mem_map(0x400000, 1024 * 1024)    # binary
mu.mem_map(0x0, 1024 * 1024)         # stack
mu.mem_write(0x400000, read("./task/fibonacci"))
mu.reg_write(UC_X86_REG_RSP, 0x0 + 1024 * 1024 - 1)

# 3. binary range
mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
mu.emu_start(0x4004E0, 0x400582)