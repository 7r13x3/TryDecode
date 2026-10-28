rule RedLine_Generic {
    meta:
        description = "Detects RedLine Stealer based on characteristic strings"
        author = "TryDecode"
        family = "RedLine"

    strings:
        $s1 = "RedLine" ascii wide
        $s2 = "address" ascii wide
        $s3 = "port" ascii wide
        $s4 = "Telegram" ascii wide
        $s5 = "Browsers" ascii wide
        $s6 = "Wallets" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        3 of them
}
