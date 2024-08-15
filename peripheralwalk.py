import argparse

from capstone import *

from unicorn import *
from unicorn.arm_const import *

import pdb
### General code flow
# open file:
#
# emulator
mu = None
# disassembler
ds = None
# binary
global_bin = None

def test_hook(uc, address, size, user_data):
    print(">>> Tracing bb at 0x%x, bs=0x%x" % (address, size))

# for hooks, we should "map" the address in automatically on an unmapped read/write

# the ANGR emulation then comes with trying to solve for return
def unmapped_read_hook(uc, access, address, size, value, user_data):
    print(">>> Unmapped Read 0x%x, Sz %d, Val %d, access %s" % (address, size, value, access))

def unmapped_write_hook(uc, access, address, size, value, user_data):
    print(">>> Unmapped Write 0x%x, Sz %d, Val %d, access %s" % (address, size, value, access))


def run_until_next_err(start_addr):
    try:
        mu.emu_start(start_addr, 1024*1024)
    except UcError as e:
        print("Got ERR: %s" % e)


def walk_binary(base, entrypoint, ram_size):

    curr_addr = entrypoint
    # for now, let's run until we get to the first exception and print out the address
    run_until_next_err(curr_addr)
    

""" Setup emu with base params """
def load_emu(binary, base, entrypoint, ram_size):
    # for now, let's just force ARM w/o thumb for testing
    global mu
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    # init our RAM
    mu.mem_map(base, ram_size)

    # map binary to RAM
    mu.mem_write(base, binary)
   
    # FTODO: setup regs and hooks
    mu.hook_add(UC_HOOK_BLOCK, test_hook)

    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, unmapped_read_hook)
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, unmapped_write_hook)

def auto_int(x):
    return int(x,0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()


    parser.add_argument("binary", type=argparse.FileType('rb'), help="Target binary to emulate.")

    parser.add_argument("-b", "--base", default=0x0, type=auto_int, help="Base address for binary")
    parser.add_argument("-e", "--entrypoint", default=0x0, type=auto_int, help="Entrypoint address for binary")
    parser.add_argument("-r", "--ram", default=1 * 1024 * 1024 * 1024, type=auto_int, help="RAM Size (default, 1G)")


    args = parser.parse_args()

    load_emu(args.binary.read(), args.base, args.entrypoint, args.ram)

    walk_binary(args.base, args.entrypoint, args.ram)
