rule Remcos_Generic {
    meta:
        description = "Detects Remcos RAT based on characteristic strings"
        author = "TryDecode"
        family = "Remcos"

    strings:
        $s1 = "Remcos" ascii wide
        $s2 = "REM" ascii wide
        $s3 = "Remcos_Mutex" ascii wide
        $s4 = "rms" ascii wide
        $s5 = "remcos" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        3 of them
}
