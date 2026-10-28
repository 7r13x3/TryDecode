rule XWorm_Generic {
    meta:
        description = "Detects XWorm based on characteristic settings strings"
        author = "TryDecode"
        family = "XWorm"

    strings:
        $s1 = "Settings" ascii wide
        $s2 = "Mutex" ascii wide
        $s3 = "InstallDir" ascii wide
        $s4 = "USBNM" ascii wide
        $s5 = "LoggerPath" ascii wide
        $s6 = "VirtualBox" ascii wide
        $s7 = "RunAntiAnalysis" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        4 of them
}
