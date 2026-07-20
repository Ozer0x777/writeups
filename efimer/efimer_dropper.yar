rule Efimer_Dropper_PyInstaller_PyArmor {
    meta:
        description  = "Efimer clipper/WordPress botnet dropper — ClickFix campaign"
        author       = "Gordon PEIRS"
        date         = "2026-07-15"
        sample       = "a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4"
        imphash      = "dcaf48c1f10b0efa0a4472200f3850ed"
        campaign_start = "2026-07-12"
        reference    = "05-efimer-payload-analysis.md"
        tlp          = "WHITE"

    strings:
        // PyInstaller + Python 3.13 indicators
        $pyi_version  = "PyInstaller-5.13.2" ascii
        $pyi_dll      = "python313.dll" ascii
        $pyi_pyz      = "PYZ-00.pyz" ascii

        // PyArmor 8.x magic (blob in .pyc)
        $pyarmor_magic = { 50 59 30 30 30 30 30 30 }   // b'PY000000'

        // XOR key — stable across all 100+ samples
        $xor_key      = "Is8xqLVw7pTB" ascii

        // Anti-sandbox check path
        $recent_path  = "Microsoft\\Windows\\Recent" wide ascii

        // C2 geo-check
        $ipinfo       = "ipinfo.io/country" ascii

        // Install path
        $install_path = "C:\\Users\\Public\\Videos\\" wide ascii

        // Tor daemon string (embedded in uusd.exe which is embedded in bundle)
        $tor_str      = "support.torproject.org" ascii

        // PyArmor nonce — unusual, potentially stable
        $nonce        = "i.non-profit" ascii

    condition:
        uint16(0) == 0x5A4D          // MZ header
        and filesize > 12MB
        and filesize < 18MB
        and $pyi_dll
        and ($pyi_version or $pyi_pyz)
        and $xor_key
        and ($recent_path or $install_path)
        and ($pyarmor_magic or $ipinfo)
}