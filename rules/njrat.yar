rule njRAT_Generic {
    meta:
        description = "Detects njRAT based on characteristic strings"
        author = "TryDecode"
        family = "njRAT"

    strings:
        $s1 = "netsh firewall" ascii wide
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $s3 = "njRAT" ascii wide
        $s4 = "BSOD" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        2 of them
}
