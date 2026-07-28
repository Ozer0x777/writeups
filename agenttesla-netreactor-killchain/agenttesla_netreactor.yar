rule AgentTesla_NetReactor_Loader_Stage1 {
    meta:
        description  = "Loader .NET stage 1 (leurre naval), dechiffre et charge AgentTesla via cle AES hardcodee"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        sample       = "bc6d86cef1b7404823c1d830387b2c9b1289c453620482fc1749dd5d2ade3897"
        tlp          = "WHITE"

    strings:
        // Cle AES 128-bit hardcodee, reutilisee comme IV -- stable sur le sample analyse
        // Chercher les deux formes : tableau d'octets inline ou chaine hex (selon compilation IL)
        $aes_key_bytes = { e4 a9 31 cb 6e 20 43 22 da 0d 1a 30 d9 46 63 3b }
        $aes_key_str   = "e4a931cb6e204322da0d1a30d946633b" ascii wide

        // Nom de la ressource .NET embarquant le stage 2
        $resource_name = "Genitalk.klaoxao.tiff" ascii wide

        // API .NET utilisee pour charger la ressource chiffree
        $resource_api  = "GetManifestResourceStream" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and ($aes_key_bytes or $aes_key_str)
        and ($resource_name or $resource_api)
}

rule AgentTesla_NetReactor_Stage2 {
    meta:
        description  = "AgentTesla stage 2, protege Eziriz .NET Reactor version non licenciee, exfil FTP"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        sample       = "39fdba7a439cb09842f26d34f84606e3cc7f685b407deceb49ee7cb71271ebcd"
        tlp          = "WHITE"

    strings:
        // Filigrane Eziriz .NET Reactor evaluation (presente en clair malgre le protecteur)
        $reactor_trial = "protected by an unregistered version of Eziriz .NET Reactor" ascii wide

        // Infrastructure C2 : FTP d'exfiltration active au moment de l'analyse
        $ftp_c2        = "ftp.piovau.com" ascii wide

        // Methode generee par le protecteur, nom stable sur ce sample
        $validate_fn   = "ValidateDetachedFunction" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and ($reactor_trial or $ftp_c2 or $validate_fn)
}
