rule SaferRAT_Android_Payload {
    meta:
        description  = "SaferRAT Android Banking Trojan (payload), operateur Diabloo, C2 gorila-panel.xyz"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        sample       = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
        tlp          = "WHITE"

    strings:
        // Nom de package du payload
        $pkg_payload  = "com.example.safeservice" ascii

        // Service d'accessibilite VNC, seul AccessibilityService declare dans le manifest
        $vnc_service  = "VncAccessibilityService" ascii

        // Tag operateur hardcode dans BotRegister.java (attribution directe)
        $operator     = "Diabloo" ascii

        // Panel C2 HTTP
        $c2_panel     = "gorila-panel.xyz" ascii

        // Endpoint d'enregistrement du bot
        $api_register = "/api/register_bot.php" ascii

        // Protocole de capture de PIN avec coordonnees exactes
        $pin_event    = "pin_click" ascii

        // Exfiltration photos vers serveur dedie, declenchee automatiquement au premier lancement
        $photo_upload = "/upload_photo" ascii

    condition:
        ($pkg_payload and ($vnc_service or $api_register))
        or ($operator and $c2_panel)
        or (3 of ($pin_event, $api_register, $photo_upload, $c2_panel, $pkg_payload))
}

rule SaferRAT_Android_Dropper {
    meta:
        description  = "SaferRAT Android dropper (com.example.nestedinstaller), installe le payload safeservice"
        author       = "Gordon PEIRS"
        date         = "2026-07"
        sample       = "d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4"
        tlp          = "WHITE"

    strings:
        $dropper_pkg = "com.example.nestedinstaller" ascii
        $payload_pkg = "com.example.safeservice" ascii

    condition:
        $dropper_pkg and $payload_pkg
}
