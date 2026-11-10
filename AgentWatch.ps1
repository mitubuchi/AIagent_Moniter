# AgentWatch — AI エージェント（Claude Code / Claude Desktop / MCP）が読み込むものと、
# PC の常駐・通信経路を記録しておき、あとから変わったところを見つける。
#
# 使い方:
#   pwsh -File AgentWatch.ps1 baseline   いまの状態を「確かめた状態」として記録する
#   pwsh -File AgentWatch.ps1 check      記録と比べ、変わったところを出す（中以上があれば終了コード 1）
#   pwsh -File AgentWatch.ps1 watch      一定間隔で check を繰り返す（-IntervalSec 300）
#   pwsh -File AgentWatch.ps1 status     エージェントの子プロセスと通信先を一覧する
#
# 読むだけで、設定もレジストリも書き換えない。書き込むのは -StateDir（既定は state\）だけ。
#
# このファイルは BOM 付き UTF-8 で保存すること。BOM が無いと Windows PowerShell 5.1 が
# ANSI として読み、日本語コメントの末尾が行継続として扱われて次の行が消える。

#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('baseline', 'check', 'watch', 'status', 'help')]
    [string]$Command = 'help',

    # プロジェクトの置き場所。直下の各フォルダーの .mcp.json / .claude / CLAUDE.md / .git を見る
    [string[]]$ProjectRoot = @('C:\Claude'),

    # 基準と記録の置き場所。USB メモリーなど PC の外に置くと、基準ごと書き換えられにくい
    [string]$StateDir,

    [int]$IntervalSec = 300,
    [int]$MaxCycles = 0,

    # レジストリ・タスク・サービス・通信経路を見ない（エージェントの設定だけを見る）
    [switch]$SkipSystem,

    # 検証用。別のフォルダーをホームに見立てて動かす
    [string]$HomeDir = $HOME,
    [string]$AppDataDir = $env:APPDATA
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web

$root = $PSScriptRoot
if (-not $StateDir) { $StateDir = Join-Path $root 'state' }
$ProjectRoot = @($ProjectRoot | ForEach-Object { $_ -split '[;,]' } | Where-Object { $_ })

$script:HomeFull = [IO.Path]::GetFullPath($HomeDir).TrimEnd('\')
$script:AppDataFull = [IO.Path]::GetFullPath($AppDataDir).TrimEnd('\')
$script:IsRealHome = ($script:HomeFull -ieq [IO.Path]::GetFullPath($HOME).TrimEnd('\'))
$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# ---------------------------------------------------------------- 小道具

function Get-Sha([string]$Text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLower()
}

function Get-FileSha([string]$Path) {
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() } catch { 'unreadable' }
}

function ConvertTo-JsonString([string]$s) {
    [System.Web.HttpUtility]::JavaScriptStringEncode($s, $true)
}

# キーの並びに左右されない JSON。同じ中身なら必ず同じ文字列になる
function ConvertTo-CanonicalJson($o) {
    if ($null -eq $o) { return 'null' }
    if ($o -is [string]) { return (ConvertTo-JsonString $o) }
    if ($o -is [bool]) { if ($o) { return 'true' } else { return 'false' } }
    if ($o -is [System.Collections.IDictionary]) {
        [string[]]$keys = @($o.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        $parts = foreach ($k in $keys) { (ConvertTo-JsonString $k) + ':' + (ConvertTo-CanonicalJson $o[$k]) }
        return '{' + (@($parts) -join ',') + '}'
    }
    if ($o -is [System.Collections.IEnumerable]) {
        $parts = foreach ($e in $o) { ConvertTo-CanonicalJson $e }
        return '[' + (@($parts) -join ',') + ']'
    }
    return [string]$o
}

function ConvertTo-JsonArray([string[]]$Values) {
    '[' + (@($Values | ForEach-Object { ConvertTo-JsonString $_ }) -join ',') + ']'
}

function Get-Rel([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith($script:AppDataFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        return '%APPDATA%' + $full.Substring($script:AppDataFull.Length)
    }
    if ($full.StartsWith($script:HomeFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        return '~' + $full.Substring($script:HomeFull.Length)
    }
    $full
}

function Read-Json([string]$Path) {
    try {
        [IO.File]::ReadAllText($Path) | ConvertFrom-Json -AsHashtable -Depth 64
    } catch { $null }
}

function Limit([string]$s, [int]$n = 300) {
    if ($s.Length -le $n) { $s } else { $s.Substring(0, $n) + '…' }
}

function Add-Entry([string]$Key, [string]$Sev, [string]$Val, [string]$Show) {
    $script:Items[$Key] = [ordered]@{ sev = $Sev; val = $Val; show = $Show }
}

function Add-Finding([string]$Sev, [string]$Where, [string]$Text) {
    $sig = "$Where|$Text"
    if ($script:FindingSeen.Add($sig)) {
        $script:Findings.Add([pscustomobject]@{ sev = $Sev; where = $Where; text = $Text })
    }
}

# ---------------------------------------------------------------- 危ない形の見分け

# 基準とは無関係に、「この書き方は確かめたほうがよい」というものを拾う。
# 当たったから悪性、外れたから安全、ではない。目視の入口にするだけ。
function Test-CommandRisk([string]$Where, [string]$Cmd, [switch]$AllowSystemTools) {
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return }
    if ($Cmd -match '(?i)\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}') {
        Add-Finding 'high' $Where 'エンコードされた PowerShell コマンドを実行する'
    }
    if ($Cmd -match '(?i)\b(iex|invoke-expression)\b|downloadstring|downloadfile|frombase64string') {
        Add-Finding 'high' $Where '取ってきた文字列を、その場でコードとして実行する形'
    }
    if ($Cmd -match '(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*(sh|bash|iex|pwsh|powershell|cmd)\b') {
        Add-Finding 'high' $Where 'ダウンロードした内容を、そのままシェルに渡す'
    }
    if (-not $AllowSystemTools -and $Cmd -match '(?i)\b(mshta|regsvr32|rundll32|bitsadmin|certutil)(\.exe)?\b') {
        Add-Finding 'medium' $Where '悪用されやすい Windows 標準コマンドを使う'
    }
    if ($Cmd -match '(?i)\\(AppData\\Local\\Temp|Windows\\Temp|Users\\Public|Downloads)\\') {
        Add-Finding 'medium' $Where '一時フォルダーやダウンロード先にあるものを実行する'
    }
    if ($Cmd -match '(?i)http://(?!localhost|127\.0\.0\.1|\[::1\])') {
        Add-Finding 'medium' $Where '暗号化されていない HTTP で外とつなぐ'
    }
    if ($Cmd -match '(?i)(?:^|[\s\\/"])(npx|bunx|uvx)(?:\.cmd|\.exe)?"?\s+(.*)$') {
        $pkg = @($Matches[2] -split '\s+' | Where-Object { $_ -and -not $_.StartsWith('-') })[0]
        if ($pkg -and $pkg -notmatch '.@\d|==\d' -and $pkg -notmatch '^[\.\\/]|^[A-Za-z]:') {
            Add-Finding 'low' $Where "版を固定せずに毎回取得して実行する（$pkg）。配布元が乗っ取られると、そのまま動く"
        }
    }
}

$script:RiskyEnv = @(
    'ANTHROPIC_BASE_URL', 'ANTHROPIC_BEDROCK_BASE_URL', 'ANTHROPIC_VERTEX_BASE_URL', 'ANTHROPIC_AUTH_TOKEN',
    'ANTHROPIC_API_KEY', 'ANTHROPIC_CUSTOM_HEADERS',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_PATH',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
    'GIT_SSH_COMMAND', 'GIT_SSH', 'GIT_ASKPASS', 'GIT_CONFIG_GLOBAL', 'GIT_EXEC_PATH',
    'PYTHONPATH', 'PYTHONSTARTUP', 'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'NPM_CONFIG_REGISTRY',
    'COMSPEC', 'PATHEXT', 'PSModulePath'
)

function Test-SettingsRisk($Json, [string]$Label) {
    $envs = $Json['env']
    if ($envs -is [System.Collections.IDictionary]) {
        foreach ($n in $envs.Keys) {
            if ($n -in $script:RiskyEnv -and $n -notin 'PSModulePath', 'PATHEXT', 'COMSPEC') {
                Add-Finding 'high' $Label "env.$n — 通信の行き先・証明書の検証・読み込むコードを変えられる変数"
            }
        }
    }
    $perm = $Json['permissions']
    if ($perm -is [System.Collections.IDictionary]) {
        if ($perm['defaultMode'] -eq 'bypassPermissions') {
            Add-Finding 'high' $Label 'permissions.defaultMode が bypassPermissions（確認なしで何でも実行する）'
        }
        foreach ($rule in @($perm['allow'])) {
            if ($rule -match '^(Bash|PowerShell)(\(\s*\*?\s*\))?$|^\*$|^mcp__\*$') {
                Add-Finding 'high' $Label "permissions.allow に何でも通す許可がある（$rule）"
            }
        }
    }
    foreach ($k in 'enableAllProjectMcpServers', 'skipDangerousModePermissionPrompt') {
        if ($Json[$k] -eq $true) { Add-Finding 'medium' $Label "$k が有効（確認の手順をひとつ飛ばす設定）" }
    }
    foreach ($k in 'apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper') {
        if ($Json[$k]) {
            Add-Finding 'medium' $Label "$k — 起動のたびに実行されるコマンド"
            Test-CommandRisk "$Label の $k" ([string]$Json[$k])
        }
    }
    $sl = $Json['statusLine']
    if ($sl -is [System.Collections.IDictionary] -and $sl['command']) {
        Add-Finding 'low' $Label 'statusLine — 画面の更新のたびに実行されるコマンド'
        Test-CommandRisk "$Label の statusLine" ([string]$sl['command'])
    }
}

# ---------------------------------------------------------------- エージェントの設定

function Format-McpShow($Def) {
    if ($Def -isnot [System.Collections.IDictionary]) { return (Limit (ConvertTo-CanonicalJson $Def)) }
    $parts = @()
    if ($Def['command']) { $parts += (@($Def['command']) + @($Def['args']) | Where-Object { $null -ne $_ }) -join ' ' }
    if ($Def['url']) { $parts += "url: $($Def['url'])" }
    foreach ($k in 'env', 'headers') {
        if ($Def[$k] -is [System.Collections.IDictionary] -and $Def[$k].Count) {
            $parts += "[$k`: " + ((@($Def[$k].Keys) | Sort-Object) -join ', ') + ']'
        }
    }
    if (-not $parts) { $parts += ConvertTo-CanonicalJson $Def }
    Limit ($parts -join '  ') 400
}

function Add-McpServers($Servers, [string]$Source) {
    if ($Servers -isnot [System.Collections.IDictionary]) { return }
    foreach ($name in @($Servers.Keys)) {
        $def = $Servers[$name]
        # 値はハッシュだけを残す（環境変数やヘッダーにトークンが入るため）。表示には名前しか出さない
        Add-Entry "mcp|$Source|$name" 'high' (Get-Sha (ConvertTo-CanonicalJson $def)) (Format-McpShow $def)
        if ($def -is [System.Collections.IDictionary]) {
            $where = "MCP サーバー「$name」（$Source）"
            $cmd = (@($def['command']) + @($def['args']) + @($def['url']) | Where-Object { $null -ne $_ }) -join ' '
            Test-CommandRisk $where $cmd
            if ($def['env'] -is [System.Collections.IDictionary]) {
                foreach ($n in $def['env'].Keys) {
                    if ($n -in $script:RiskyEnv -and $n -notlike 'ANTHROPIC_API_KEY') {
                        Add-Finding 'medium' $where "env.$n — 通信の行き先・証明書の検証・読み込むコードを変えられる変数"
                    }
                }
            }
        }
    }
}

function Get-HookLines($Hooks) {
    $out = [System.Collections.Generic.List[string]]::new()
    if ($Hooks -isnot [System.Collections.IDictionary]) { return , $out }
    foreach ($evt in $Hooks.Keys) {
        foreach ($group in @($Hooks[$evt])) {
            if ($group -isnot [System.Collections.IDictionary]) { continue }
            foreach ($h in @($group['hooks'])) {
                if ($h -isnot [System.Collections.IDictionary]) { continue }
                $body = if ($h['command']) { $h['command'] } elseif ($h['url']) { $h['url'] } elseif ($h['prompt']) { "prompt: $($h['prompt'])" } else { ConvertTo-CanonicalJson $h }
                $out.Add("$evt[$($group['matcher'])] $body")
            }
        }
    }
    , $out
}

$script:SensitiveSettings = @(
    'apiKeyHelper', 'statusLine', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper',
    'enableAllProjectMcpServers', 'enabledMcpjsonServers', 'disabledMcpjsonServers',
    'enabledPlugins', 'extraKnownMarketplaces', 'sandbox', 'skipDangerousModePermissionPrompt',
    'autoMemoryDirectory', 'fileSuggestion', 'forceLoginMethod', 'allowedMcpServers', 'deniedMcpServers'
)

function Add-SettingsFile([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $j = Read-Json $Path
    if ($j -isnot [System.Collections.IDictionary]) {
        Add-Entry "setting|$Label|(全体)" 'high' (Get-FileSha $Path) 'JSON として読めないので、ファイル全体のハッシュで見ている'
        return
    }
    foreach ($k in @($j.Keys)) {
        $v = $j[$k]
        if ($k -in 'mcpServers', 'servers') {
            Add-McpServers $v $Label
        } elseif ($k -eq 'permissions' -and $v -is [System.Collections.IDictionary]) {
            foreach ($pk in @($v.Keys)) {
                $c = ConvertTo-CanonicalJson $v[$pk]
                Add-Entry "setting|$Label|permissions.$pk" 'medium' (Get-Sha $c) $c
            }
        } elseif ($k -eq 'env' -and $v -is [System.Collections.IDictionary]) {
            # 値は出さない。名前と、値のハッシュの頭だけ
            $c = ConvertTo-JsonArray @(@($v.Keys) | Sort-Object | ForEach-Object { "$_ #" + (Get-Sha ([string]$v[$_])).Substring(0, 8) })
            Add-Entry "setting|$Label|env" 'high' (Get-Sha $c) $c
        } elseif ($k -eq 'hooks') {
            $lines = Get-HookLines $v
            $c = ConvertTo-JsonArray @($lines | Sort-Object)
            Add-Entry "setting|$Label|hooks" 'high' (Get-Sha (ConvertTo-CanonicalJson $v)) $c
            foreach ($line in $lines) {
                Add-Finding 'low' $Label "フック: $(Limit $line 160)"
                Test-CommandRisk "$Label のフック" $line
            }
        } else {
            $c = ConvertTo-CanonicalJson $v
            $sev = if ($k -in $script:SensitiveSettings) { 'high' } else { 'low' }
            Add-Entry "setting|$Label|$k" $sev (Get-Sha $c) (Limit $c)
        }
    }
    Test-SettingsRisk $j $Label
}

# ~/.claude.json は使用状況も書き込まれて頻繁に変わる。動作を決める欄だけを抜き出す
function Add-ClaudeJson([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $label = Get-Rel $Path
    $j = Read-Json $Path
    if ($j -isnot [System.Collections.IDictionary]) {
        Add-Entry "setting|$label|(全体)" 'high' 'unparsable' 'JSON として読めない'
        return
    }
    Add-McpServers $j['mcpServers'] "$label（全体）"
    $projects = $j['projects']
    if ($projects -is [System.Collections.IDictionary]) {
        foreach ($proj in @($projects.Keys)) {
            $p = $projects[$proj]
            if ($p -isnot [System.Collections.IDictionary]) { continue }
            Add-McpServers $p['mcpServers'] "$label [$proj]"
            foreach ($f in 'enabledMcpjsonServers', 'disabledMcpjsonServers', 'allowedTools') {
                if (@($p[$f]).Count -gt 0 -and $null -ne $p[$f]) {
                    $c = ConvertTo-CanonicalJson $p[$f]
                    Add-Entry "setting|$label [$proj]|$f" 'medium' (Get-Sha $c) $c
                }
            }
            if ($p['hasTrustDialogAccepted'] -eq $true) {
                Add-Entry "trust|$proj" 'low' 'true' 'このフォルダーを信頼済みにしている'
            }
        }
    }
}

# ---------------------------------------------------------------- ファイル

function Add-File([string]$Path, [string]$Sev, [string]$Prefix = 'file') {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $fi = Get-Item -LiteralPath $Path -Force
    Add-Entry "$Prefix|$(Get-Rel $Path)" $Sev (Get-FileSha $Path) ("{0} バイト、更新 {1:yyyy-MM-dd HH:mm}" -f $fi.Length, $fi.LastWriteTime)
}

function Add-Tree([string]$Dir, [string]$Sev, [string]$Prefix = 'file', [int]$Max = 400) {
    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return }
    $files = @(Get-ChildItem -LiteralPath $Dir -Recurse -File -Force -ErrorAction SilentlyContinue | Sort-Object FullName)
    if ($files.Count -le $Max) {
        foreach ($f in $files) { Add-File $f.FullName $Sev $Prefix }
        return
    }
    # 多すぎるフォルダーは 1 件にまとめる（どのファイルかは分からないが、変わったことは分かる）
    $sb = [System.Text.StringBuilder]::new()
    foreach ($f in $files) { [void]$sb.Append($f.FullName).Append('|').Append((Get-FileSha $f.FullName)).Append("`n") }
    Add-Entry "$Prefix|$(Get-Rel $Dir)\（全体）" $Sev (Get-Sha $sb.ToString()) "$($files.Count) ファイルをまとめて 1 件"
}

# CLAUDE.md と、そこから @ で取り込まれるファイル。毎回プロンプトに入るので、書き換えは指示の乗っ取りになる
function Add-Instruction([string]$Path, [int]$Depth = 0) {
    if ($Depth -gt 4 -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    if ($script:Items.Contains("file|$(Get-Rel $Path)")) { return }
    Add-File $Path 'medium'
    $dir = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        foreach ($m in [regex]::Matches($line, '(?:^|\s)@([^\s`]+)')) {
            $ref = $m.Groups[1].Value
            if ($ref -notmatch '[\\/]' -and $ref -notmatch '\.md$') { continue }
            $target = if ($ref.StartsWith('~')) { $script:HomeFull + $ref.Substring(1) }
                      elseif ([IO.Path]::IsPathRooted($ref)) { $ref }
                      else { Join-Path $dir $ref }
            try { Add-Instruction $target ($Depth + 1) } catch { }
        }
    }
}

# git の設定のうち、コマンドを実行させられる欄だけを抜き出す
function Get-GitRisky([string]$Path) {
    $out = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return , $out }
    $sec = ''
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*\[(.+?)\]\s*$') { $sec = $Matches[1]; continue }
        if ($line -match '^\s*([\w\.\-]+)\s*=\s*(.*)$') {
            $k = $Matches[1]; $v = $Matches[2]
            $exec = $k -match '^(?i)(hooksPath|fsmonitor|sshCommand|askPass|editor|pager|helper|program|textconv|command|insteadOf|pushInsteadOf|path|proxy|sslVerify|sslCAInfo|driver|clean|smudge|process)$'
            if ($exec -or ($sec -match '^(?i)alias' -and $v.TrimStart().StartsWith('!'))) { $out.Add("$sec.$k=$v") }
        }
    }
    , $out
}

function Add-GitConfig([string]$Path, [string]$Label, [switch]$Always) {
    $lines = Get-GitRisky $Path
    if ($lines.Count -eq 0 -and -not $Always) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $c = ConvertTo-JsonArray @($lines)
    Add-Entry "gitcfg|$Label" 'medium' (Get-Sha $c) $c
    foreach ($l in $lines) {
        if ($l -match '(?i)\.(hooksPath|sshCommand|askPass)=' -or $l -match '(?i)\.fsmonitor=(?!true|false)' -or
            $l -match '(?i)\.sslVerify=false' -or $l -match '(?i)insteadOf=') {
            Add-Finding 'medium' $Label "git の設定: $(Limit $l 160)"
        }
    }
}

# 資格情報は中身を見ない（トークンは更新で変わる）。誰が読めるかだけを見る
function Add-Acl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $label = Get-Rel $Path
    try {
        $acl = Get-Acl -LiteralPath $Path
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $lines = foreach ($r in $rules) {
            $sid = $r.IdentityReference.Value
            $name = try { $r.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $sid }
            if ($r.AccessControlType -eq 'Allow' -and $sid -in 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-7') {
                Add-Finding 'high' $label "この PC の誰でも読める（$name に許可がある）"
            }
            "$name $($r.AccessControlType) $($r.FileSystemRights)"
        }
        $c = ConvertTo-JsonArray @($lines | Sort-Object -Unique)
        Add-Entry "cred|$label" 'high' (Get-Sha $c) $c
    } catch {
        Add-Entry "cred|$label" 'high' 'unreadable' 'アクセス権を読めなかった'
    }
}

function Add-HomeItems {
    $h = $script:HomeFull
    $a = $script:AppDataFull
    $c = Join-Path $h '.claude'

    Add-ClaudeJson (Join-Path $h '.claude.json')
    Add-SettingsFile (Join-Path $c 'settings.json') '~\.claude\settings.json'
    Add-SettingsFile (Join-Path $c 'settings.local.json') '~\.claude\settings.local.json'
    Add-Instruction (Join-Path $c 'CLAUDE.md')
    foreach ($d in 'skills', 'commands', 'agents', 'hooks', 'rules', 'output-styles', 'plugins') {
        Add-Tree (Join-Path $c $d) 'medium'
    }
    Add-File (Join-Path $c 'keybindings.json') 'low'

    # 自動メモリは Claude 自身が書き換える。次の会話に持ち越される指示なので、低で見ておく
    $proj = Join-Path $c 'projects'
    if (Test-Path -LiteralPath $proj) {
        foreach ($m in Get-ChildItem -LiteralPath $proj -Directory -ErrorAction SilentlyContinue) {
            Add-Tree (Join-Path $m.FullName 'memory') 'low' 'memory'
        }
    }

    # Claude Desktop
    $desk = Join-Path $a 'Claude'
    Add-SettingsFile (Join-Path $desk 'claude_desktop_config.json') '%APPDATA%\Claude\claude_desktop_config.json'
    Add-Tree (Join-Path $desk 'Claude Extensions') 'medium'
    Add-File (Join-Path $desk 'extensions-installations.json') 'medium'
    if ($script:IsRealHome) {
        # MSIX 版はここに振り替えられていることがある
        foreach ($p in Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue) {
            $alt = Join-Path $p.FullName 'LocalCache\Roaming\Claude\claude_desktop_config.json'
            Add-SettingsFile $alt "(MSIX $($p.Name)) claude_desktop_config.json"
        }
    }

    # ほかのエージェント。あれば見る
    foreach ($f in '.cursor\mcp.json', '.codeium\windsurf\mcp_config.json', '.gemini\settings.json') {
        Add-SettingsFile (Join-Path $h $f) "~\$f"
    }
    Add-SettingsFile (Join-Path $a 'Code\User\mcp.json') '%APPDATA%\Code\User\mcp.json'
    Add-File (Join-Path $h '.codex\config.toml') 'high'

    # シェルが起動のたびに読むもの。エージェントがコマンドを実行するたびに一緒に動く
    $docs = if ($script:IsRealHome) { [Environment]::GetFolderPath('MyDocuments') } else { Join-Path $h 'Documents' }
    foreach ($d in 'PowerShell', 'WindowsPowerShell') {
        foreach ($f in 'profile.ps1', 'Microsoft.PowerShell_profile.ps1', 'Microsoft.VSCode_profile.ps1') {
            Add-File (Join-Path $docs "$d\$f") 'high' 'shell'
        }
    }
    foreach ($f in '.bashrc', '.bash_profile', '.bash_login', '.profile', '.zshrc', '.ssh\config', '.ssh\authorized_keys', '.ssh\rc') {
        Add-File (Join-Path $h $f) 'high' 'shell'
    }
    foreach ($f in '.npmrc', '.yarnrc', '.yarnrc.yml', 'pip\pip.ini', '.config\pip\pip.conf', '.wslconfig') {
        Add-File (Join-Path $h $f) 'medium' 'shell'
    }
    Add-GitConfig (Join-Path $h '.gitconfig') '~\.gitconfig' -Always

    # 資格情報
    Add-Acl (Join-Path $c '.credentials.json')
    Add-Acl (Join-Path $a 'GitHub CLI\hosts.yml')
    $ssh = Join-Path $h '.ssh'
    if (Test-Path -LiteralPath $ssh) {
        foreach ($k in Get-ChildItem -LiteralPath $ssh -File -Force -ErrorAction SilentlyContinue) {
            if ($k.Name -match '^id_' -and $k.Extension -ne '.pub') { Add-Acl $k.FullName }
        }
    }
}

function Add-ProjectItems {
    foreach ($r in $ProjectRoot) {
        if (-not (Test-Path -LiteralPath $r -PathType Container)) { continue }
        $dirs = @(Get-Item -LiteralPath $r) + @(Get-ChildItem -LiteralPath $r -Directory -Force -ErrorAction SilentlyContinue)
        foreach ($d in $dirs) {
            $p = $d.FullName
            foreach ($f in '.mcp.json', '.cursor\mcp.json', '.vscode\mcp.json') {
                Add-SettingsFile (Join-Path $p $f) (Join-Path $p $f)
            }
            foreach ($f in '.claude\settings.json', '.claude\settings.local.json') {
                Add-SettingsFile (Join-Path $p $f) (Join-Path $p $f)
            }
            foreach ($f in 'CLAUDE.md', 'CLAUDE.local.md', '.claude\CLAUDE.md', 'AGENTS.md') {
                Add-Instruction (Join-Path $p $f)
            }
            foreach ($f in 'skills', 'commands', 'agents', 'hooks', 'rules') {
                Add-Tree (Join-Path $p ".claude\$f") 'medium'
            }
            # git のフックは、エージェントが commit するときに一緒に動く
            $gh = Join-Path $p '.git\hooks'
            if (Test-Path -LiteralPath $gh -PathType Container) {
                foreach ($f in Get-ChildItem -LiteralPath $gh -File -Force -ErrorAction SilentlyContinue) {
                    if ($f.Extension -ne '.sample') { Add-File $f.FullName 'high' 'githook' }
                }
            }
            Add-GitConfig (Join-Path $p '.git\config') (Join-Path $p '.git\config')
        }
    }
}

# ---------------------------------------------------------------- PC の常駐と通信経路

function Add-RegValues([string]$KeyPath, [string]$Prefix, [string]$Sev, [string[]]$Only) {
    $k = Get-Item -LiteralPath $KeyPath -ErrorAction SilentlyContinue
    if (-not $k) { return }
    foreach ($n in $k.GetValueNames()) {
        if ($Only -and $n -notin $Only) { continue }
        $v = (@($k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) -join ' ')
        Add-Entry "$Prefix|$KeyPath|$n" $Sev $v (Limit $v 400)
        if ($Prefix -eq 'run') { Test-CommandRisk "自動起動「$n」（$KeyPath）" $v }
    }
}

function Get-Stable([string]$Path) {
    # 更新のたびに変わる版番号を均す（そのままだと、更新のたびに「変更」と出る）
    $Path -replace '\d+\.\d+\.\d+(\.\d+)*', '<版>'
}

function Add-SystemItems {
    $cv = 'Software\Microsoft\Windows\CurrentVersion'
    Add-RegValues "HKCU:\$cv\Run" 'run' 'high'
    Add-RegValues "HKLM:\$cv\Run" 'run' 'high'
    Add-RegValues "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" 'run' 'high'
    Add-RegValues "HKCU:\$cv\RunOnce" 'run' 'medium'
    Add-RegValues "HKLM:\$cv\RunOnce" 'run' 'medium'
    Add-RegValues 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'run' 'high' @('Shell', 'Userinit')
    Add-RegValues 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'run' 'high' @('Shell', 'Userinit')
    Add-RegValues 'HKCU:\Environment' 'run' 'high' @('UserInitMprLogonScript')
    # cmd.exe が起動のたびに実行するコマンド。エージェントが cmd を呼ぶたびに動く
    Add-RegValues 'HKCU:\Software\Microsoft\Command Processor' 'run' 'high' @('AutoRun')
    Add-RegValues 'HKLM:\Software\Microsoft\Command Processor' 'run' 'high' @('AutoRun')

    foreach ($sf in 'Startup', 'CommonStartup') {
        $dir = [Environment]::GetFolderPath($sf)
        if ($dir -and (Test-Path -LiteralPath $dir)) {
            foreach ($f in Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue) {
                if ($f.Name -ne 'desktop.ini') { Add-File $f.FullName 'high' 'startup' }
            }
        }
    }

    foreach ($t in Get-ScheduledTask) {
        $acts = foreach ($a in @($t.Actions)) {
            if ($a.Execute) { ("$($a.Execute) $($a.Arguments)").Trim() }
            elseif ($a.ClassId) { "COM:$($a.ClassId)" }
            else { $a.CimClass.CimClassName }
        }
        $v = Get-Stable ((@($acts) -join ' ; ') + " [実行: $($t.Principal.UserId)$($t.Principal.GroupId)]" + $(if ($t.State -eq 'Disabled') { ' [無効]' }))
        Add-Entry "task|$($t.TaskPath)$($t.TaskName)" 'medium' $v (Limit $v 400)
        # Microsoft のタスクは rundll32 などを普通に使うので、形の検査は外のものだけ
        if ($t.TaskPath -notlike '\Microsoft\*') { Test-CommandRisk "タスク $($t.TaskPath)$($t.TaskName)" (@($acts) -join ' ; ') }
    }

    foreach ($s in Get-CimInstance Win32_Service -Property Name, PathName, StartMode, StartName) {
        # ユーザーごとのサービスは、サインインのたびに末尾の番号が変わる
        $name = $s.Name -replace '_[0-9a-f]{4,8}$', '_*'
        # 手動と自動は Windows 自身が行き来させる（BITS で実測）。比べるのは「無効かどうか」まで
        $state = if ($s.StartMode -eq 'Disabled') { '無効' } else { '有効' }
        $path = Get-Stable ([string]$s.PathName)
        Add-Entry "service|$name" 'medium' "$path [$state, $($s.StartName)]" (Limit "$path [$state（$($s.StartMode)）, $($s.StartName)]" 400)
    }

    # 待ち受け。ポートは出入りが多いので、「どのプログラムが」「外から届く形で」だけを比べる
    $byPid = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Group-Object OwningProcess
    $merged = @{}
    foreach ($g in $byPid) {
        $proc = Get-Process -Id ([int]$g.Name) -ErrorAction SilentlyContinue
        $who = if ($proc -and $proc.Path) { Get-Stable $proc.Path } elseif ($proc) { $proc.ProcessName } else { "pid $($g.Name)" }
        if (-not $merged.ContainsKey($who)) { $merged[$who] = @{ net = $false; ports = [System.Collections.Generic.SortedSet[int]]::new() } }
        foreach ($c in $g.Group) {
            if ($c.LocalAddress -notin '127.0.0.1', '::1') { $merged[$who].net = $true }
            [void]$merged[$who].ports.Add([int]$c.LocalPort)
        }
    }
    foreach ($who in $merged.Keys) {
        $scope = if ($merged[$who].net) { 'ほかの機械から届く' } else { 'この PC の中だけ' }
        $sev = if ($merged[$who].net) { 'medium' } else { 'low' }
        Add-Entry "listen|$who" $sev $scope "$scope（ポート $((@($merged[$who].ports) | Select-Object -First 12) -join ', ')）"
    }

    Add-RegValues "HKCU:\$cv\Internet Settings" 'proxy' 'high' @('ProxyEnable', 'ProxyServer', 'AutoConfigURL', 'ProxyOverride')

    foreach ($scope in 'User', 'Machine') {
        foreach ($n in $script:RiskyEnv) {
            $v = [Environment]::GetEnvironmentVariable($n, $scope)
            if ($null -ne $v) {
                $secret = $n -match '(?i)TOKEN|KEY|HEADERS'
                Add-Entry "env|$scope|$n" 'high' (Get-Sha $v) $(if ($secret) { '（値は出さない）' } else { Limit $v 400 })
                if ($n -notin 'PSModulePath', 'PATHEXT', 'COMSPEC', 'NO_PROXY', 'ANTHROPIC_API_KEY') {
                    Add-Finding 'medium' "環境変数（$scope）" "$n が設定されている — 通信の行き先・証明書の検証・読み込むコードを変えられる変数"
                }
            }
        }
        $path = [Environment]::GetEnvironmentVariable('Path', $scope)
        if ($path) {
            $c = ConvertTo-JsonArray @($path -split ';' | Where-Object { $_ })
            Add-Entry "env|$scope|Path" 'medium' (Get-Sha $c) $c
        }
    }

    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hosts) {
        $active = @([IO.File]::ReadAllLines($hosts) | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
        $c = ConvertTo-JsonArray $active
        Add-Entry 'hosts|hosts' 'high' (Get-Sha $c) $c
        foreach ($l in $active) {
            if ($l -match '(?i)anthropic|claude|github|npmjs|pypi|nuget|microsoft') {
                Add-Finding 'high' 'hosts' "配布元や API の行き先を書き換える行: $l"
            }
        }
    }

    # 信頼されたルート証明書。足されると、暗号化された通信を途中で読み替えられる
    $lm = @{}
    foreach ($cert in Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue) {
        $lm[$cert.Thumbprint] = $true
        Add-Entry "cert|LocalMachine|$($cert.Thumbprint)" 'medium' 'present' (Limit $cert.Subject 200)
    }
    foreach ($cert in Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue) {
        if (-not $lm.ContainsKey($cert.Thumbprint)) {
            Add-Entry "cert|CurrentUser|$($cert.Thumbprint)" 'high' 'present' (Limit $cert.Subject 200)
            Add-Finding 'low' '信頼されたルート証明書' "このユーザーにだけ入っている: $(Limit $cert.Subject 120)"
        }
    }

    foreach ($f in "$PSHOME\profile.ps1", "$PSHOME\Microsoft.PowerShell_profile.ps1",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1") {
        Add-File $f 'high' 'shell'
    }
    foreach ($f in 'managed-settings.json', 'managed-mcp.json') {
        Add-SettingsFile (Join-Path $env:ProgramData "ClaudeCode\$f") "%ProgramData%\ClaudeCode\$f"
    }

    # Claude Code 本体。自動更新でハッシュは変わるので、署名で見る
    $bins = @((Get-Command claude -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source,
        (Join-Path $script:HomeFull '.local\bin\claude.exe')) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    foreach ($b in $bins) {
        if ($b -notmatch '\.exe$') { Add-File $b 'high' 'bin'; continue }
        $sig = Get-AuthenticodeSignature -LiteralPath $b
        $v = "$($sig.Status) / $($sig.SignerCertificate.Subject)"
        Add-Entry "bin|$(Get-Rel $b)" 'high' $v $v
        if ($sig.Status -ne 'Valid') { Add-Finding 'high' (Get-Rel $b) "署名が有効でない（$($sig.Status)）" }
    }
    # Claude Desktop が抱えている Claude Code。版ごとにフォルダーが変わるので、署名の種類をまとめて 1 件にする
    # （ワイルドカードのパスに -Recurse -Depth を付けると 1 件も返らないので、フォルダーごとに探す）
    $bundled = @(Get-ChildItem (Join-Path $script:AppDataFull 'Claude') -Directory -Filter 'claude-code*' -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Recurse -Depth 3 -Filter 'claude.exe' -File -ErrorAction SilentlyContinue })
    if ($bundled.Count) {
        $kinds = foreach ($b in $bundled) {
            $sig = Get-AuthenticodeSignature -LiteralPath $b.FullName
            if ($sig.Status -ne 'Valid') { Add-Finding 'high' (Get-Rel $b.FullName) "署名が有効でない（$($sig.Status)）" }
            "$($sig.Status) / $($sig.SignerCertificate.Subject)"
        }
        $c = ConvertTo-JsonArray @($kinds | Sort-Object -Unique)
        Add-Entry 'bin|%APPDATA%\Claude\claude-code*\（各版の claude.exe）' 'high' (Get-Sha $c) $c
    }
}

# ---------------------------------------------------------------- 収集・比較・表示

function New-Snapshot {
    $script:Items = @{}
    $script:Findings = [System.Collections.Generic.List[object]]::new()
    $script:FindingSeen = [System.Collections.Generic.HashSet[string]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()

    $steps = [ordered]@{ 'エージェントの設定' = { Add-HomeItems }; 'プロジェクト' = { Add-ProjectItems } }
    if (-not $SkipSystem) { $steps['PC の常駐と通信経路'] = { Add-SystemItems } }
    foreach ($name in $steps.Keys) {
        # 途中で失敗しても黙って減らさない。取れなかったことを結果に残す
        try { & $steps[$name] } catch { $failed.Add("$name`: $($_.Exception.Message)") }
    }

    $sorted = [ordered]@{}
    foreach ($k in ($script:Items.Keys | Sort-Object)) { $sorted[$k] = $script:Items[$k] }
    [ordered]@{
        meta     = [ordered]@{
            created = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            machine = $env:COMPUTERNAME
            system  = (-not $SkipSystem)
            script  = (Get-FileSha $PSCommandPath)
        }
        items    = $sorted
        findings = @($script:Findings)
        failed   = @($failed)
    }
}

function Compare-Snapshot($OldItems, $NewItems) {
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $NewItems.Keys) {
        $n = $NewItems[$k]
        if (-not $OldItems.Contains($k)) {
            $out.Add([pscustomobject]@{ kind = '追加'; key = $k; sev = $n.sev; old = $null; new = $n.show })
        } elseif ($OldItems[$k].val -ne $n.val) {
            $out.Add([pscustomobject]@{ kind = '変更'; key = $k; sev = $n.sev; old = $OldItems[$k].show; new = $n.show })
        }
    }
    foreach ($k in $OldItems.Keys) {
        if (-not $NewItems.Contains($k)) {
            $out.Add([pscustomobject]@{ kind = '削除'; key = $k; sev = $OldItems[$k].sev; old = $OldItems[$k].show; new = $null })
        }
    }
    $rank = @{ high = 0; medium = 1; low = 2 }
    , @($out | Sort-Object @{ Expression = { $rank[$_.sev] } }, key)
}

$script:SevWord = @{ high = '高'; medium = '中'; low = '低' }
$script:SevColor = @{ high = 'Red'; medium = 'Yellow'; low = 'DarkGray' }
$script:CatWord = @{
    mcp = 'MCP サーバー'; setting = 'エージェントの設定'; trust = '信頼済みフォルダー'; file = '指示・スキル'
    memory = '自動メモリ'; shell = 'シェルの起動時に読むもの'; gitcfg = 'git の設定'; githook = 'git のフック'
    cred = '資格情報の読める範囲'; run = '自動起動'; startup = 'スタートアップ'; task = 'タスク'; service = 'サービス'
    listen = '待ち受け'; proxy = 'プロキシ'; env = '環境変数'; hosts = 'hosts'; cert = 'ルート証明書'; bin = 'Claude Code 本体'
}

function Get-ArrayOrNull([string]$s) {
    if (-not $s -or -not $s.StartsWith('[')) { return $null }
    try { , @($s | ConvertFrom-Json -NoEnumerate | ForEach-Object { $_ } | ForEach-Object { [string]$_ }) } catch { $null }
}

function Write-Diff($d) {
    $cat, $rest = $d.key -split '\|', 2
    $word = if ($script:CatWord.ContainsKey($cat)) { $script:CatWord[$cat] } else { $cat }
    Write-Host ("[{0}] {1}  {2}: {3}" -f $script:SevWord[$d.sev], $d.kind, $word, $rest) -ForegroundColor $script:SevColor[$d.sev]
    if ($d.sev -eq 'low') { return }
    $oa = Get-ArrayOrNull $d.old
    $na = Get-ArrayOrNull $d.new
    if ($d.kind -eq '変更' -and $null -ne $oa -and $null -ne $na) {
        foreach ($x in $na) { if ($x -notin $oa) { Write-Host "       + $x" } }
        foreach ($x in $oa) { if ($x -notin $na) { Write-Host "       - $x" } }
    } elseif ($d.kind -eq '変更') {
        if ($d.old -eq $d.new) {
            Write-Host "       $($d.new)"
            Write-Host '       （見えている部分は同じ。出していない値 — 環境変数やヘッダー、ファイルの中身 — が変わった）'
        } else {
            Write-Host "       前: $($d.old)"
            Write-Host "       後: $($d.new)"
        }
    } elseif ($d.kind -eq '追加') {
        Write-Host "       $($d.new)"
    } else {
        Write-Host "       （あったもの）$($d.old)"
    }
}

function Write-Findings($Snap) {
    $list = @($Snap.findings)
    if ($Snap.failed.Count) {
        Write-Host ''
        Write-Host '■ 取れなかったもの（この範囲は確かめられていない）' -ForegroundColor Red
        foreach ($f in $Snap.failed) { Write-Host "  $f" -ForegroundColor Red }
    }
    if (-not $list.Count) { return }
    $rank = @{ high = 0; medium = 1; low = 2 }
    Write-Host ''
    Write-Host '■ いまの設定のうち、目で確かめておきたいもの（基準とは無関係。形だけで拾っている）'
    foreach ($f in ($list | Sort-Object @{ Expression = { $rank[$_.sev] } }, where)) {
        Write-Host ("[{0}] {1}" -f $script:SevWord[$f.sev], $f.where) -ForegroundColor $script:SevColor[$f.sev]
        Write-Host "       $($f.text)"
    }
}

function Save-Json($Object, [string]$Path) {
    [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 8), $script:Utf8NoBom)
}

function Read-Baseline {
    $path = Join-Path $StateDir 'baseline.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $b = [IO.File]::ReadAllText($path) | ConvertFrom-Json -AsHashtable -Depth 16
    $b['_sha'] = Get-FileSha $path
    $b
}

function Write-Log($Diffs) {
    $log = Join-Path $StateDir 'events.log'
    $now = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $sb = [System.Text.StringBuilder]::new()
    foreach ($d in $Diffs) {
        $line = [ordered]@{ time = $now; sev = $d.sev; kind = $d.kind; key = $d.key; old = $d.old; new = $d.new } | ConvertTo-Json -Compress
        [void]$sb.Append($line).Append("`n")
    }
    [IO.File]::AppendAllText($log, $sb.ToString(), $script:Utf8NoBom)
}

function Get-Counts($Diffs) {
    $h = @($Diffs | Where-Object sev -eq 'high').Count
    $m = @($Diffs | Where-Object sev -eq 'medium').Count
    $l = @($Diffs | Where-Object sev -eq 'low').Count
    "高 $h / 中 $m / 低 $l"
}

# ---------------------------------------------------------------- コマンド

function Invoke-Baseline {
    [void](New-Item -ItemType Directory -Force -Path $StateDir)
    $path = Join-Path $StateDir 'baseline.json'
    $old = Read-Baseline
    $snap = New-Snapshot
    if ($old) {
        $diffs = Compare-Snapshot $old.items $snap.items
        Copy-Item -LiteralPath $path -Destination (Join-Path $StateDir 'baseline.prev.json') -Force
        Write-Host "前の基準から $($diffs.Count) 件の変化を、確かめたものとして取り込む（$(Get-Counts $diffs)）。"
        Write-Host '前の基準は baseline.prev.json に残した。'
    }
    Save-Json ([ordered]@{ meta = $snap.meta; items = $snap.items }) $path
    Write-Host "基準を記録した: $path"
    Write-Host "  項目 $($snap.items.Count) 件"
    Write-Host "  指紋 $(Get-FileSha $path)"
    Write-Host '  この指紋を PC の外（紙・スマホ）に控えておくと、基準ごと書き換えられたときに気づける。'
    Write-Findings $snap
    0
}

function Invoke-Check {
    $base = Read-Baseline
    if (-not $base) {
        Write-Host '基準がまだ無い。先に baseline を実行する。' -ForegroundColor Yellow
        return 2
    }
    $snap = New-Snapshot
    Write-Host "基準: $($base.meta.created) に記録（指紋 $($base._sha.Substring(0, 16))…）"
    if ($base.meta.script -ne $snap.meta.script) {
        Write-Host '[高] このスクリプト自身が、基準を記録したときから変わっている。' -ForegroundColor Red
    }
    if ([bool]$base.meta.system -ne [bool]$snap.meta.system) {
        Write-Host '（基準と今回で -SkipSystem の指定が違う。PC 側の項目が、追加や削除として出る）' -ForegroundColor Yellow
    }
    $diffs = Compare-Snapshot $base.items $snap.items
    Write-Host ''
    if ($diffs.Count -eq 0) {
        Write-Host "■ 基準から変わったところは無い（$($snap.items.Count) 項目）" -ForegroundColor Green
    } else {
        Write-Host "■ 基準から変わったところ: $($diffs.Count) 件（$(Get-Counts $diffs)）"
        foreach ($d in $diffs) { Write-Diff $d }
        Write-Log $diffs
    }
    Write-Findings $snap
    $serious = @($diffs | Where-Object sev -ne 'low').Count
    if ($serious -or $snap.failed.Count -or $base.meta.script -ne $snap.meta.script) { 1 } else { 0 }
}

function Invoke-Watch {
    $base = Read-Baseline
    if (-not $base) {
        Write-Host '基準がまだ無い。先に baseline を実行する。' -ForegroundColor Yellow
        return 2
    }
    Write-Host "見張りを始める（$IntervalSec 秒ごと。Ctrl+C で止める）。基準: $($base.meta.created)"
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $cycle = 0
    $code = 0
    while ($true) {
        $cycle++
        $base = Read-Baseline
        $snap = New-Snapshot
        $diffs = Compare-Snapshot $base.items $snap.items
        $fresh = @($diffs | Where-Object { $seen.Add("$($_.kind)|$($_.key)|$($_.new)") })
        if ($fresh.Count) {
            Write-Host ''
            Write-Host "$((Get-Date).ToString('HH:mm:ss')) 新しい変化 $($fresh.Count) 件（$(Get-Counts $fresh)）"
            foreach ($d in $fresh) { Write-Diff $d }
            Write-Log $fresh
            if (@($fresh | Where-Object sev -ne 'low').Count) { $code = 1; [Console]::Beep(880, 300) }
        }
        foreach ($f in $snap.failed) { Write-Host "取れなかった: $f" -ForegroundColor Red }
        if ($MaxCycles -gt 0 -and $cycle -ge $MaxCycles) { break }
        Start-Sleep -Seconds $IntervalSec
    }
    $code
}

function Invoke-Status {
    $all = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate)
    $byId = @{}
    foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p }
    # PID は使い回される。親のほうが新しいなら、それは本当の親ではない
    $parentOf = {
        param($p)
        $par = $byId[[int]$p.ParentProcessId]
        if ($par -and $par.ProcessId -ne $p.ProcessId -and (-not $par.CreationDate -or -not $p.CreationDate -or $par.CreationDate -le $p.CreationDate)) { $par }
    }
    $kids = @{}
    foreach ($p in $all) {
        $par = & $parentOf $p
        if ($par) {
            $id = [int]$par.ProcessId
            if (-not $kids.ContainsKey($id)) { $kids[$id] = [System.Collections.Generic.List[object]]::new() }
            $kids[$id].Add($p)
        }
    }
    $isAgent = { param($p) $p -and $p.Name -match '^(?i)claude(-code)?(\.exe)?$' }
    $roots = @($all | Where-Object { (& $isAgent $_) -and -not (& $isAgent (& $parentOf $_)) })
    if (-not $roots.Count) {
        Write-Host 'Claude のプロセスは動いていない。'
        return 0
    }

    $remote = @{}
    foreach ($c in Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue) {
        if ($c.RemoteAddress -in '127.0.0.1', '::1') { continue }
        $id = [int]$c.OwningProcess
        if (-not $remote.ContainsKey($id)) { $remote[$id] = [System.Collections.Generic.SortedSet[string]]::new() }
        [void]$remote[$id].Add("$($c.RemoteAddress):$($c.RemotePort)")
    }
    $sig = @{}
    $stat = @{ procs = 0; unsigned = [System.Collections.Generic.SortedSet[string]]::new(); remotes = [System.Collections.Generic.SortedSet[string]]::new() }

    $walk = {
        param($p, [int]$depth)
        $stat.procs++
        $tag = ''
        $exe = $p.ExecutablePath
        if ($exe) {
            if (-not $sig.ContainsKey($exe)) {
                $sig[$exe] = try { [string](Get-AuthenticodeSignature -LiteralPath $exe).Status } catch { 'Unknown' }
            }
            if ($sig[$exe] -ne 'Valid') { $tag = ' [署名なし]'; [void]$stat.unsigned.Add($exe) }
        }
        $cmd = [string]$p.CommandLine
        # コマンド行に入っている秘密を画面に出さない
        $cmd = $cmd -replace '(?i)((?:token|secret|password|passwd|api[-_]?key|authorization|bearer)\S*?[=:\s]+)\S+', '$1***'
        $pad = '  ' * $depth
        $color = if ($tag) { 'Yellow' } elseif ($depth -eq 0) { 'Cyan' } else { 'Gray' }
        Write-Host ("{0}{1} ({2}){3}  {4}" -f $pad, $p.Name, $p.ProcessId, $tag, (Limit $cmd 120)) -ForegroundColor $color
        if ($remote.ContainsKey([int]$p.ProcessId)) {
            $r = @($remote[[int]$p.ProcessId])
            foreach ($x in $r) { [void]$stat.remotes.Add($x) }
            Write-Host ("{0}  → {1}{2}" -f $pad, (($r | Select-Object -First 6) -join ', '), $(if ($r.Count -gt 6) { " ほか $($r.Count - 6)" })) -ForegroundColor DarkCyan
        }
        if ($depth -lt 12 -and $kids.ContainsKey([int]$p.ProcessId)) {
            foreach ($k in ($kids[[int]$p.ProcessId] | Sort-Object CreationDate)) { & $walk $k ($depth + 1) }
        }
    }
    Write-Host '■ Claude から起動されているプロセスと、その通信先'
    foreach ($r in $roots) { & $walk $r 0 }
    Write-Host ''
    Write-Host "プロセス $($stat.procs) 個 / 外への接続先 $($stat.remotes.Count) か所 / 署名のない実行ファイル $($stat.unsigned.Count) 個"
    foreach ($u in $stat.unsigned) { Write-Host "  署名なし: $u" -ForegroundColor Yellow }
    0
}

function Show-Help {
    Write-Host @'
AgentWatch — AI エージェントが読み込むものと、PC の常駐・通信経路の変化を見つける

  pwsh -File AgentWatch.ps1 baseline   いまの状態を「確かめた状態」として記録する
  pwsh -File AgentWatch.ps1 check      記録と比べ、変わったところを出す
  pwsh -File AgentWatch.ps1 watch      一定間隔で check を繰り返す
  pwsh -File AgentWatch.ps1 status     Claude の子プロセスと通信先を一覧する

  -ProjectRoot C:\Claude,D:\Work   プロジェクトの置き場所（既定 C:\Claude）
  -StateDir E:\agentwatch          基準と記録の置き場所（既定 state\）
  -IntervalSec 300                 watch の間隔
  -SkipSystem                      レジストリ・タスク・サービス・通信経路を見ない

check の終了コード: 0 = 変化なし（低だけを含む） / 1 = 中以上の変化、または取れなかった項目がある / 2 = 基準が無い
'@
    0
}

$code = switch ($Command) {
    'baseline' { Invoke-Baseline }
    'check' { Invoke-Check }
    'watch' { Invoke-Watch }
    'status' { Invoke-Status }
    default { Show-Help }
}
exit ([int]@($code)[-1])
