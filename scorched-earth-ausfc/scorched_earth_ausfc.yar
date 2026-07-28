/*
   Ransomware Prinz Eugen (nom de projet Go interne "scorched-earth-ausfc"),
   module de chiffrement : mot de passe code en dur derriere un schema
   Argon2id/HKDF/ChaCha20-Poly1305 par ailleurs sain. Voir writeup.md pour
   le detail complet, et §9 pour l'attribution a la famille via une analyse
   externe ThreatDown (echantillon distinct, servertool.exe).

   Auteur : Gordon PEIRS (@ozer0x777)
   TLP:CLEAR
*/

rule PrinzEugen_encrypter_scorched_earth_ausfc
{
    meta:
        description = "Ransomware Prinz Eugen (module encrypter) : chemin de build interne, module Go et chaine HKDF caracteristiques"
        author      = "Gordon PEIRS (@ozer0x777)"
        date        = "2026-07-27"
        malware     = "Prinz Eugen"
        family      = "Ransomware (Go), module de chiffrement"
        tlp         = "CLEAR"

    strings:
        $path   = "scorched-earth-ausfc/cmd/encrypter/main.go" ascii
        $module = "scorched-earth-ausfc" ascii
        $hkdf   = "scorched-earth key v1" ascii
        $magic  = "CHV1" ascii
        $ext    = ".prinzeugen" ascii wide

        $mz = "MZ"

    condition:
        $mz at 0 and filesize < 20MB and (1 of ($path, $hkdf) or 2 of ($module, $magic, $ext))
}

rule PrinzEugen_sample_IOCs
{
    meta:
        description = "IOC : hash de l'echantillon de chiffrement analyse ici, et de l'echantillon distinct rapporte par ThreatDown (source externe, non verifie localement)"
        author = "Gordon PEIRS (@ozer0x777)"
        date   = "2026-07-27"
        hash_sha256_encrypter_analyse_ici = "88e63d1f5f5478bb98269bb48c7508c6fc90f1f203f37aa7b30b801080b55fbd"
        hash_sha256_servertool_threatdown = "686213cc11d36af764de824801bced9366dfca3823fe0d51b752f74149bcf1f4"
        reference = "https://www.threatdown.com/blog/prinz-eugen-ransomware-a-deep-dive-into-a-new-go-based-encryptor/"
        tlp = "CLEAR"

    strings:
        $ext = ".prinzeugen" ascii wide

    condition:
        $ext
}
