#[
    Credits to: @snovvcrash from the NimHollow Project: https://github.com/snovvcrash/NimHollow

    Nim implementaiton of some simple sandbox detection methods from the OSEP course by @offensive-security.   
]#

import winim/lean
import random
import os
import times

proc isEmulated*(): bool =
    # Check if we're in a sandbox by calling a rare-emulated API
    let mem = VirtualAllocExNuma(
        GetCurrentProcess(),
        NULL,
        0x1000,
        0x3000, # MEM_COMMIT | MEM_RESERVE
        0x20, # PAGE_EXECUTE_READ
        0)

    if isNil(mem):
        return true
    return false


proc sleepAndCheck*(): bool =
    # Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
    randomize()
    let dreaming = rand(5000..10000)
    let delta = dreaming - 500
    let before = now()
    sleep(dreaming)
    if (now() - before).inMilliseconds < delta:
        return false
    return true

