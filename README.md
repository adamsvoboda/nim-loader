# nim-loader 

a work-in-progress adventure into learning nim by cobbling resources together to create 
a shellcode loader that implements common EDR/AV evasion techniques.


### Instructions
- Replace the byte array in `loader.nim` with your own x64 shellcode
- Compile the EXE and run it: `nim c -d:danger -d:strip --opt:size "loader.nim"`
- Probably adjust which process you want to inject into by looking in the .nim files of the injection folder method you're using...

### Completed Features
- Direct syscalls dynamically resolved from NTDLL (Thanks @ShitSecure)
- AMSI and ETW patching (Thanks @byt3bl33d3r)
- NTDLL unhooking (Thanks @MrUn1k0d3r)
- CreateRemoteThread injection (Thanks @byt3bl33d3r, @ShitSecure)

### WIP Features
- Process Hollowing Technique (Thanks @snovvcrash)
- Shellcode encryption/decryption using [AES in CTR mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR) (Thanks @snovvcrash)
- Replace all compatible API calls with syscalls
- Add template generator and compiler, cmdline args for shellcode, injection methods, process paths, etc.

### Obfuscation
- Consider using [denim](https://github.com/moloch--/denim) by @LittleJoeTables for obfuscator-llvm nim compilation support!


### References & Inspiration
- OffensiveNim by Marcello Salvati (@byt3bl33d3r)
- NimlineWhispers2 by Alfie Champion (@ajpc500)
- SysWhispers3 by klezVirus (@KlezVirus)
- NimPackt-v1 by Cas van Cooten (@chvancooten)
- unhook_bof.c by Mr. Un1k0d3r (@MrUn1k0d3r)
- NimGetSyscallStub by S3cur3Th1sSh1t (@ShitSecure)
- NimHollow by snovvcrash (@snovvcrash)

### Examples
<p align="center">
    <img src="screenshots/example.png">
</p>