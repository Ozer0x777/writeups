rule AsgardProtector_AutoIt_IExpress {
    meta:
        description  = "Dropper IExpress + AutoIt (Asgard Protector) deployant StealC, campagne 2026-07"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        sample       = "afbeeeaa7952579bc73b5d220ef1a828ecfdb62b80e339b007f07c82c60ab6da"
        tlp          = "WHITE"

    strings:
        // AutoIt compiled script magic, embeds in IExpress CAB resource (.rsrc ~95% of file)
        $autoit_magic  = ">>>AUTOIT SCRIPT<<<" ascii
        $autoit_noncmd = ">>>AUTOIT NO CMDEXECUTE<<<" ascii

        // Anti-VM string constants compared against hardware/process names at runtime
        // Present in plaintext in the compiled .a3x function body
        $anti_vm1 = "XeN:" ascii
        $anti_vm2 = "XeNa" ascii
        $anti_vm3 = "xeNe" ascii

        // Function name table entry in compiled .a3x (XOR decode routine for all obfuscated strings)
        $decrypt_fn = "BATHROOMREWARDLIVED" ascii

        // IExpress stub: imports Cabinet.dll for embedded CAB extraction
        $cabinet = "cabinet.dll" ascii nocase

    condition:
        uint16(0) == 0x5A4D
        and ($autoit_magic or $autoit_noncmd)
        and (1 of ($anti_vm1, $anti_vm2, $anti_vm3))
        and ($decrypt_fn or $cabinet)
}

rule AsgardProtector_AutoIt_Persistence {
    meta:
        description  = "Artefacts de persistance du loader Asgard Protector (InnoCoder + dossier de demarrage + RunOnce)"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        tlp          = "WHITE"

    strings:
        // Fichiers de persistance deposes par le loader (noms reconstruits depuis les ChrW obfusques)
        $lnk = "InnoCoder.lnk" ascii wide
        $vbs = "InnoCoder.vbs" ascii wide
        $dir = "CodeInnovate Technologies Co" ascii wide

        // Injection : section mappee localement, copiee vers le process cible via NtWriteVirtualMemory
        $nt_map   = "NtMapViewOfSection" ascii
        $nt_write = "NtWriteVirtualMemory" ascii
        $nt_ctx   = "NtSetContextThread" ascii

    condition:
        uint16(0) == 0x5A4D
        and ($lnk or $vbs or $dir)
        and (1 of ($nt_map, $nt_write, $nt_ctx))
}

rule StealC_Payload_C2_202607 {
    meta:
        description  = "StealC payload (post-injection), config C2 campagne 2026-07 -- sur dump memoire ou sample extrait"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        tlp          = "WHITE"

    strings:
        $c2_ip  = "160.20.109.75" ascii
        $c2_php = "d19ca32cb5a444ac8b87.php" ascii
        $run    = "CurrentVersion\\RunOnce" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and $c2_ip
        and $c2_php
}
