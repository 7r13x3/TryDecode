rule DcRAT_Generic {
    meta:
        description = "Detects DcRAT (AsyncRAT Fork)"
        author = "TryDecode"
        family = "DcRAT"

    strings:
        $s1 = "DcRat" ascii wide
        $s2 = "Client.Algorithm" ascii wide
        $s3 = "Settings" ascii wide
        $s4 = "Aes256" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        3 of them
}

rule VenomRAT_Generic {
    meta:
        description = "Detects VenomRAT (AsyncRAT Fork)"
        author = "TryDecode"
        family = "VenomRAT"

    strings:
        $s1 = "VenomRAT" ascii wide
        $s2 = "Client.Algorithm" ascii wide
        $s3 = "Settings" ascii wide
        $s4 = "Aes256" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        3 of them
}
