rule QuasarRAT_Generic {
    meta:
        description = "Detects QuasarRAT based on characteristic strings and namespaces"
        author = "TryDecode"
        family = "QuasarRAT"

    strings:
        $s1 = "Quasar.Client" ascii wide
        $s2 = "Quasar.Common" ascii wide
        $s3 = "Quasar.Server" ascii wide
        $s4 = "GetSettings" ascii wide
        $s5 = "Aes128" ascii wide
        $s6 = "Aes256" ascii wide
        $s7 = "MessagePack" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        3 of them
}
