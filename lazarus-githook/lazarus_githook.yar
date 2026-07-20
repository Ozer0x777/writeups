/*
  Lazarus Group — DEV#POPPER / Contagious Interview
  Git hook infection chain targeting developers
  SHA256 samples:
    a129de4f...sh  — git hook (stage 0)
    02e6fbf7...unknown — stage 1 JS controller
    a3f41333...js  — stage 2 JS C2 beaconer
    683a1607...js  — stage 3 JS dropper
    b34aa84e...py  — Python browser stealer
    cd3b606d...py  — Python C2 comms module
*/

rule Lazarus_DEV_POPPER_GitHook
{
    meta:
        description = "Lazarus DEV#POPPER malicious git hook — OS-specific curl/wget dropper"
        hash_sha256 = "a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c"
        author = "Gordon PEIRS"
        date = "2026-07-20"
        tlp = "WHITE"

    strings:
        $sh_case     = "case \"$OSTYPE\" in"
        $darwin_curl = "144.172.103.226/301/301m"
        $linux_wget  = "144.172.103.226/301/301l"
        $windows_cmd = "144.172.103.226/301/301w"
        $redir       = "> /dev/null 2>&1 &"

    condition:
        $sh_case and 2 of ($darwin_curl, $linux_wget, $windows_cmd) and $redir
}

rule Lazarus_DEV_POPPER_Stage1_JS
{
    meta:
        description = "Lazarus DEV#POPPER stage 1 JS stealer+loader — obfuscator.io rot=112, 22 crypto wallet extensions, Solana/Exodus, upload 95.216.64.240:1224/uploads"
        hash_sha256 = "02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5"
        author = "Gordon PEIRS"
        date = "2026-07-20"
        tlp = "WHITE"

    strings:
        $arr_fn      = "function a3a()"
        $lookup      = "function a3b("
        $enc1        = "'yxrPB24'"
        $enc2        = "'uKXqz3K'"
        $enc3        = "'z2LWzM4'"
        $enc4        = "'mJe0mJGWmfDkDgrcCG'"
        $enc5        = "'mJmYnJaWmMrAs3jMsa'"
        // Stealer-specific: constant key holding MetaMask extension ID
        $metamask_key = "'kjFvU'"
        // Stealer-specific: MetaMask extension ID fragments (present as literals in obfuscated source)
        $metamask_b  = "'fbeog'"
        $metamask_c  = "'fgpgk'"
        // Stealer-specific: Phantom (Solana) extension ID fragment
        $phantom     = "'bfnae'"
        // Stealer-specific: constant key holding upload URL (http://95.216.64.240:1224/uploads)
        $upload_key  = "'uGuaJ'"
        // Stealer-specific: staging directory path fragment
        $n3_dir      = "'/.n3'"

    condition:
        $arr_fn and $lookup and
        3 of ($enc1, $enc2, $enc3, $enc4, $enc5) and
        2 of ($metamask_key, $metamask_b, $metamask_c, $phantom, $upload_key, $n3_dir)
}

rule Lazarus_DEV_POPPER_Stage2_JS
{
    meta:
        description = "Lazarus DEV#POPPER stage 2 JS C2 beaconer — obfuscator.io, array D, rotation 46, IP 95.217.102.138"
        hash_sha256 = "a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27"
        author = "Gordon PEIRS"
        date = "2026-07-20"
        tlp = "WHITE"

    strings:
        $arr_fn    = "function D()"
        $enc1      = "'nJq0odq2me14ywTUEa'"
        $enc2      = "'mtCZndiZotbUq3rAuNm'"
        $enc3      = "'ntCZnMf3CwHUtq'"
        $enc4      = "'jZTNBg8'"
        $campaign  = "'30620700'"
        $iife_tgt  = "0xcc8a4"

    condition:
        $arr_fn and $campaign and $iife_tgt and 2 of ($enc1, $enc2, $enc3, $enc4)
}

rule Lazarus_DEV_POPPER_Stage3_JS
{
    meta:
        description = "Lazarus DEV#POPPER stage 3 JS dropper — obfuscator.io, array j, rotation 70, Cloudflare R2 CDN"
        hash_sha256 = "683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630"
        author = "Gordon PEIRS"
        date = "2026-07-20"
        tlp = "WHITE"

    strings:
        $arr_fn  = "function j()"
        $enc1    = "'zMLUAxnO'"
        $enc2    = "'BGOGicaG'"
        $enc3    = "'iIbDicyM'"
        $enc4    = "'swfusNG'"
        $enc5    = "'EfvoB3u'"

    condition:
        $arr_fn and 3 of ($enc1, $enc2, $enc3, $enc4, $enc5)
}

rule Lazarus_DEV_POPPER_Python_Stealer
{
    meta:
        description = "Lazarus DEV#POPPER browser stealer — Chrome/Brave/Opera/Edge/Yandex, passwords + credit cards, C2 95.216.64.240:1224"
        hash_sha256 = "b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1"
        author = "Gordon PEIRS"
        date = "2026-07-20"
        tlp = "WHITE"

    strings:
        $host      = "HOST = '95.216.64.240'"
        $port      = "PORT = 1224"
        $stype     = "sType = \"36\""
        $gtype     = "gType = \"700\""
        $endpoint  = "/keys"
        $stealer   = "Chrome Safe Storage"
        $cards     = "credit_cards"

    condition:
        $host and $port and ($stype or $gtype) and $endpoint and ($stealer or $cards)
}

rule Lazarus_DEV_POPPER_Python_RAT
{
    meta:
        description = "Lazarus DEV#POPPER Python RAT — keylogger + clipboard + TCP C2 69.197.164.135:2245, eval/exec, .env exfil"
        hash_sha256 = "cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6"
        author = "Gordon PEIRS"
        date = "2026-07-20"
        tlp = "WHITE"

    strings:
        $host_http = "HOST = '95.216.64.240'"
        $host_tcp  = "HOST0 = '69.197.164.135'"
        $port_tcp  = "PORT0 = 2245"
        $lock      = "lock_file = '.poc2'"
        $heartbeat = "HEARTBEAT_CODE = 98"
        $rat_dir   = "\".n2\""
        $eval_cmd  = "ssh_eval"
        $env_exfil = "ssh_env"

    condition:
        ($host_http or $host_tcp) and $lock and 3 of ($port_tcp, $heartbeat, $rat_dir, $eval_cmd, $env_exfil)
}
