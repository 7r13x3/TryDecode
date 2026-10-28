rule AsyncRAT_Generic {
    meta:
        description = "Detects AsyncRAT and its forks (DcRAT, VenomRAT)"
        author = "TryDecode"
        family = "AsyncRAT"

    strings:
        $s1 = "AsyncClient" ascii wide
        $s2 = "Client.Algorithm" ascii wide
        $s3 = "Settings" ascii wide
        $s4 = "Aes256" ascii wide
        $s5 = "Plugin.dll" ascii wide
        $s6 = "pastebin" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        3 of them
}
