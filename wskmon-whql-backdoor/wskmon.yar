rule WSKMON_WFP_Kernel_Backdoor {
    meta:
        description  = "wskmon.sys : backdoor kernel WFP passif, trigger 4 octets + HMAC-SHA256, injection SSDT dans svchost SYSTEM"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        sample       = "495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979"
        cert_serial  = "330000013c4a61fb3578d2b6dd00000000013c"
        tlp          = "WHITE"

    strings:
        // 4 octets declencheurs du backdoor, identifes dans le flux TCP inspecte par le callout WFP
        $trigger_magic = { 7F 4E 54 46 }

        // Noms WFP enregistres au chargement (presents en clair dans .rdata)
        $sublayer = "WskMon Sub" ascii wide
        $callout  = "WskMon Callout" ascii wide
        $filter   = "WskMon Filter" ascii wide

        // Cle XOR 32 octets a l'offset 0x140005470, indexee via (eax & 0x1f)
        $xor_key = {
            d2 47 8a 1e f3 6b c0 95 54 29 e7 3d 81 af 66 0c
            b8 72 1f e4 43 9d 5e 28 a6 0d 73 c9 3b 84 f1 52
        }

        // Primitives CNG pour le HMAC-SHA256 de validation des paquets declencheurs
        $bcrypt_create = "BCryptCreateHash" ascii wide
        $bcrypt_data   = "BCryptHashData" ascii wide

        // Sequence d'opcodes du scan SSDT via MSR IA32_LSTAR (lea r10, [rip+...])
        $ssdt_scan = { 4C 8D 15 }

    condition:
        uint16(0) == 0x5A4D
        and (2 of ($sublayer, $callout, $filter))
        and ($xor_key or ($bcrypt_create and $trigger_magic))
}

rule WSKMON_Family_WFP_SharedPattern {
    meta:
        description  = "Famille wskmon.sys/devhost.sys/844ljfpvz.sys : meme certificat WHQL compromis, patterns WFP communs"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        note         = "Couvre les 3 samples compiles entre 2026-01 et 2026-04, soumis par le meme compte MalwareBazaar (smica83)"
        tlp          = "WHITE"

    strings:
        // Appels WFP communs aux trois samples
        $wfp_filter  = "FwpmFilterAdd0" ascii wide
        $wfp_callout = "FwpsCalloutRegister1" ascii wide
        $wfp_engine  = "FwpmEngineOpen0" ascii wide

        // Validation HMAC, commune aux trois
        $bcrypt = "BCryptCreateHash" ascii wide

        // devhost.sys specifique : primitive de lecture/ecriture memoire physique
        $device_name = "\\Device\\devhost" ascii wide
        $phys_map    = "MmMapIoSpace" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and (2 of ($wfp_filter, $wfp_callout, $wfp_engine))
        and $bcrypt
}
