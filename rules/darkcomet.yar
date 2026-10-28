rule DarkComet_Generic {
    meta:
        description = "Detects DarkComet RAT based on characteristic strings"
        author = "TryDecode"
        family = "DarkComet"

    strings:
        $s1 = "DarkComet" ascii wide
        $s2 = "FWB" ascii wide
        $s3 = "DC_MUTEX" ascii wide
        $s4 = "Server.exe" ascii wide
        $s5 = "Plugins" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        3 of them
}
