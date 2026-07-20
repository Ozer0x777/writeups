/*
   InfernoGrabber v9.0 (aka "DeepSeek browser ransomware")
   Stealer / ransomware Python monofichier (serveur Flask + frontend embarque),
   attribue a une generation par le LLM DeepSeek, commentaires de code en russe.

   Toutes les chaines ci-dessous ont ete verifiees presentes dans l'echantillon
   (lecture directe partielle du code reel via l'extrait statique du rapport
   sandbox CAPE Linux sur VirusTotal). Les chaines non verifiables depuis la
   portion lue (ex. chemins de cookies au-dela de la troncature) sont volontairement
   exclues. Fichier encode en UTF-8 : les litteraux cyrilliques correspondent aux
   octets UTF-8 de l'echantillon (lui-meme UTF-8).

   Auteur    : Gordon PEIRS (@ozer0x777)
   Reference : https://research.checkpoint.com/2026/browser-only-ransomware-from-llm-hallucinations-to-a-practical-attack-technique/
   TLP:CLEAR
*/

rule InfernoGrabber_DeepSeek_LLM_Stealer
{
    meta:
        description = "InfernoGrabber v9.0 : stealer/ransomware Python genere par LLM (DeepSeek), backend Flask + schema SQLite InfernoDB"
        author      = "Gordon PEIRS (@ozer0x777)"
        date        = "2026-07-20"
        malware     = "InfernoGrabber"
        family      = "PyStealer / TrojanRansom"
        reference   = "https://research.checkpoint.com/2026/browser-only-ransomware-from-llm-hallucinations-to-a-practical-attack-technique/"
        hash_sha256 = "07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5"
        tlp         = "CLEAR"

    strings:
        // Ossature specifique au projet
        $class = "class InfernoDB" ascii
        $db    = "inferno.db" ascii
        $log   = "inferno.log" ascii
        $fern  = "Fernet.generate_key" ascii

        // Tables du schema SQLite (combinaison distinctive)
        $t_vict = "CREATE TABLE IF NOT EXISTS victims" ascii
        $t_disc = "discord_tokens" ascii
        $t_card = "credit_cards" ascii
        $t_cryp = "crypto_wallets" ascii
        $t_keys = "keystrokes" ascii
        $t_cam  = "webcam_captures" ascii
        $t_mic  = "microphone_captures" ascii

        // Bibliotheques natives importees (pile stealer host-level)
        $i_cookie = "import browser_cookie3" ascii
        $i_auto   = "import pyautogui" ascii
        $i_clip   = "import pyperclip" ascii
        $i_sock   = "from flask_sock import Sock" ascii

        // Commentaires de section en russe (theme "Enfer / Ад")
        $ru_conf = "КОНФИГ АДА" ascii
        $ru_base = "БАЗА ДАННЫХ АДА" ascii
        $ru_init = "ИНИЦИАЛИЗАЦИЯ" ascii

    condition:
        filesize < 3MB
        and $class
        and 2 of ($db, $log, $fern)
        and 3 of ($t_*)
        and ( 2 of ($i_*) or 1 of ($ru_*) )
}

rule InfernoGrabber_DeepSeek_known_webhook
{
    meta:
        description = "IOC : webhook Discord d'exfiltration du sample InfernoGrabber connu (webhook mort au moment de l'analyse, cree le 25/01/2026)"
        author      = "Gordon PEIRS (@ozer0x777)"
        date        = "2026-07-20"
        hash_sha256 = "07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5"
        tlp         = "CLEAR"

    strings:
        $wh   = "discord.com/api/webhooks/1465066143516459277/" ascii
        $whid = "1465066143516459277" ascii

    condition:
        any of them
}
