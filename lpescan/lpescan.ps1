# ======================================================================
# lpescan.ps1 — scanner LPE ala PEAS + CVE matcher (port PowerShell dari lpescan.py)
# Target: Windows dengan Windows PowerShell 5.1 / PowerShell 7+. Tanpa python.
# Read-only: scanner TIDAK PERNAH mengeksekusi PoC.
# Data (dihasilkan build-scanner.py): lpe-cves-win.tsv, lpe-cve-meta.tsv,
#   lpe-pocs.tsv, lpe-winrelease.tsv, lpe-winprivs.tsv, lpe-info.tsv
# ======================================================================
[CmdletBinding()]
param(
  [string]$Report = "",
  [switch]$JsonOnly,
  [switch]$NoColor,
  [switch]$Selftest
)

$SCANNER_VERSION = "1.2.0"
$IMPL = "powershell"

# data TSV: di sebelah script (unit deploy dist/), atau dist/ di atasnya (mesin dev)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DataDir = $ScriptDir
if (-not (Test-Path (Join-Path $ScriptDir "lpe-cves-win.tsv"))) {
  $DataDir = Join-Path $ScriptDir "dist"
}
$D_CVES_WIN = Join-Path $DataDir "lpe-cves-win.tsv"
$D_META     = Join-Path $DataDir "lpe-cve-meta.tsv"
$D_POCS     = Join-Path $DataDir "lpe-pocs.tsv"
$D_WINREL   = Join-Path $DataDir "lpe-winrelease.tsv"
$D_WINPRIVS = Join-Path $DataDir "lpe-winprivs.tsv"
$D_INFO     = Join-Path $DataDir "lpe-info.tsv"

# ---- warna (ANSI, sama dengan python/bash) ----
$ESC = [char]27
if ($NoColor) {
  $C_R = ""; $C_B = ""; $C_G = ""; $C_DIM = ""; $C_RB = ""; $C_M = ""; $C_MB = ""; $C_Y = ""
  $S_CRIT = ""; $S_HIGH = ""; $S_MED = ""; $S_LOW = ""; $S_INFO = ""
} else {
  $C_R = "$ESC[0m";     $C_B = "$ESC[1m";  $C_G = "$ESC[32m"; $C_DIM = "$ESC[2m"
  $C_RB = "$ESC[1;31m"; $C_M = "$ESC[35m"; $C_MB = "$ESC[1;35m"; $C_Y = "$ESC[33m"
  $S_CRIT = "$ESC[1;31m"; $S_HIGH = "$ESC[1;33m"; $S_MED = "$ESC[33m"
  $S_LOW = "$ESC[36m"; $S_INFO = "$ESC[37m"
}

function Paint([string]$s, [string]$col) {
  if ($col) { return "$col$s$C_R" }
  return "$s$C_R"
}

# ======================================================================
# Mesin versi — parity _parts/normalize_num/cmp_version lpescan.py
# ======================================================================

function Toks([string]$s) {
  # parity _parts(): run digit & huruf jadi token, huruf lowercase, pemisah dibuang
  # (filter: hanya token murni digit ATAU murni huruf — bukan sekadar non-kosong)
  $t = [regex]::Replace($s.ToLowerInvariant(), "[0-9]+|[a-z]+", "|`$0|")
  return ,@($t -split "\|" | Where-Object { $_ -match "^[0-9]+$|^[a-z]+$" })
}

function Norm([string]$s) {
  # parity normalize_num(): hanya digit (int64), buang trailing zero
  $digits = @([regex]::Matches($s, "[0-9]+") | ForEach-Object { [int64]$_.Value })
  while ($digits.Count -gt 0 -and $digits[$digits.Count - 1] -eq 0) {
    if ($digits.Count -eq 1) { $digits = @(); break }   # hindari 0..-1 (indeks negatif!)
    $digits = @($digits[0..($digits.Count - 2)])
  }
  return ,$digits
}

function NList([string]$s) {
  # kolom n TSV ("5 15 100") -> array int; "-"/"" -> list kosong
  if ($null -eq $s -or $s -eq "-" -or $s -eq "") { return ,@() }
  return ,@($s -split " " | ForEach-Object { [int64]$_ })
}

function CmpV($a, $b) {
  # parity cmp_version/_cmp_list: numeric > alpha, prefix lebih pendek < lebih panjang
  $a = @($a); $b = @($b)
  $n = [Math]::Min($a.Count, $b.Count)
  for ($i = 0; $i -lt $n; $i++) {
    $va = [string]$a[$i]; $vb = [string]$b[$i]
    $ta = $va -match "^[0-9]+$"; $tb = $vb -match "^[0-9]+$"
    if ($ta -and $tb) {
      $ia = [int64]$va; $ib = [int64]$vb
      if ($ia -eq $ib) { continue }
      if ($ia -lt $ib) { return -1 } else { return 1 }
    }
    if (-not $ta -and -not $tb) {
      if ([string]::CompareOrdinal($va, $vb) -eq 0) { continue }
      if ([string]::CompareOrdinal($va, $vb) -lt 0) { return -1 } else { return 1 }
    }
    if ($ta) { return 1 } else { return -1 }
  }
  if ($a.Count -eq $b.Count) { return 0 }
  if ($a.Count -gt $b.Count) { return 1 } else { return -1 }
}

function EvalRow([string[]]$row, $pv, [string]$mode) {
  # parity eval_row awk — offset 0-based: [9]=op1 [10]=v1 [11]=n1 [12]=op2 [13]=v2 [14]=n2 [15]=op3 [16]=v3 [17]=n3
  # MODE t: banding token mentah vs toks(v) ; MODE n: banding list int vs kolom n
  # (pv kosong TIDAK di-guard: python _cmp_list([], qv) = -1 -> op "<" tetap True)
  $pv = @($pv)
  for ($i = 0; $i -lt 3; $i++) {
    $op = $row[9 + 3 * $i]; $v = $row[10 + 3 * $i]; $nn = $row[11 + 3 * $i]
    if ($op -eq "-") { continue }
    if ($op -eq "ALL") { return $true }
    if ($op -eq "EXACT") {
      $qv = if ($mode -eq "t") { @(Toks $v) } else { @(NList $nn) }
      if ((CmpV $pv $qv) -ne 0) { return $false }
      continue
    }
    $qv = if ($mode -eq "t") { @(Toks $v) } else { @(NList $nn) }
    $c = CmpV $pv $qv
    if ($op -eq "<")  { if ($c -ge 0) { return $false }; continue }
    if ($op -eq "<=") { if ($c -gt 0) { return $false }; continue }
    if ($op -eq ">")  { if ($c -le 0) { return $false }; continue }
    if ($op -eq ">=") { if ($c -lt 0) { return $false }; continue }
    return $false  # op tak dikenal -> parity python return False
  }
  return $true
}

# ======================================================================
# Util
# ======================================================================

function JEsc([string]$s) {
  # escape \ dan " ; \t\r\n jadi \t\r\n (parity json.dumps) ; kontrol lain dibuang
  # (urutan: backslash DULU, sisanya menyusul — hasil \t tidak boleh ter-escape ulang)
  if ($null -eq $s) { return "" }
  $s = [regex]::Replace($s, "[\x00-\x08\x0B\x0C\x0E-\x1F]", "")
  $s = $s.Replace("\", "\\")
  $s = $s.Replace('"', '\"')
  $s = $s.Replace("`t", "\t")
  $s = $s.Replace("`r", "\r")
  $s = $s.Replace("`n", "\n")
  return $s
}

function JStr([string]$s) {
  return '"' + (JEsc $s) + '"'
}

function JN($v) {
  # "-"/""/$null -> null (kolom TSV absen)
  if ($null -eq $v -or "$v" -eq "" -or "$v" -eq "-") { return "null" }
  return "$v"
}

function JStrN($v) {
  # string yang mungkin absen: "-"/""/$null -> null, selainnya quoted (severity/published)
  if ($null -eq $v -or "$v" -eq "" -or "$v" -eq "-") { return "null" }
  return JStr "$v"
}

# ======================================================================
# Data loading
# ======================================================================
$script:RowsByCpe = @{}                       # cpe -> List[string[18]]
$script:CpeOrder  = New-Object System.Collections.Generic.List[string]
$script:MetaById  = @{}                       # id -> desc
$script:PocById   = @{}                       # id -> List[@{repo;url}]
$script:WinRel    = @{}                       # prod -> @{token -> build}
$script:WinRelOrder = @{}                     # prod -> List[token] urutan TSV (last-match-wins)
$script:WinPrivs  = @{}                       # priv -> saran
$script:CveCount  = 0
$script:DatasetGen = "-"

function Load-WinRelease {
  # ladder release->build: urutan baris TSV = urutan dict tables.py,
  # lookup build->token (Get-WinFacts) harus iterasi urutan ini (python last-match-wins)
  $script:WinRel = @{}
  $script:WinRelOrder = @{}
  foreach ($line in [System.IO.File]::ReadLines($D_WINREL)) {
    $f = $line.Split("`t")
    if ($f.Count -lt 3) { continue }
    $prod = $f[0]; $tok = $f[1]
    if (-not $script:WinRel.ContainsKey($prod)) {
      $script:WinRel[$prod] = @{}
      $script:WinRelOrder[$prod] = New-Object System.Collections.Generic.List[string]
    }
    $script:WinRel[$prod][$tok] = [int]$f[2]
    [void]$script:WinRelOrder[$prod].Add($tok)
  }
}

function Load-Data {
  foreach ($f in @($D_CVES_WIN, $D_META, $D_POCS, $D_WINREL, $D_WINPRIVS, $D_INFO)) {
    if (-not (Test-Path $f)) {
      Write-Output "[!] $f tidak ditemukan — jalankan build-scanner.py di mesin arsip, lalu copy dist/."
      exit 1
    }
  }
  # lpe-cves-win.tsv: 18 kolom, sentinel "-" (tidak pernah ada field kosong)
  foreach ($line in [System.IO.File]::ReadLines($D_CVES_WIN)) {
    $f = $line.Split("`t")
    if ($f.Count -lt 18) { continue }
    $cpe = $f[7]
    if (-not $script:RowsByCpe.ContainsKey($cpe)) {
      $script:RowsByCpe[$cpe] = New-Object System.Collections.Generic.List[string[]]
      [void]$script:CpeOrder.Add($cpe)   # urutan first-appearance = parity idx python
    }
    $script:RowsByCpe[$cpe].Add($f)
  }
  foreach ($line in [System.IO.File]::ReadLines($D_META)) {
    $f = $line.Split("`t")
    if ($f.Count -lt 2) { continue }
    if (-not $script:MetaById.ContainsKey($f[0])) { $script:MetaById[$f[0]] = $f[1] }
  }
  foreach ($line in [System.IO.File]::ReadLines($D_POCS)) {
    $f = $line.Split("`t")
    if ($f.Count -lt 3) { continue }
    if (-not $script:PocById.ContainsKey($f[0])) {
      $script:PocById[$f[0]] = New-Object System.Collections.Generic.List[object]
    }
    $script:PocById[$f[0]].Add(@{ repo = $f[1]; url = $f[2] })
  }
  Load-WinRelease
  foreach ($line in [System.IO.File]::ReadLines($D_WINPRIVS)) {
    $f = $line.Split("`t")
    if ($f.Count -lt 2) { continue }
    if (-not $script:WinPrivs.ContainsKey($f[0])) { $script:WinPrivs[$f[0]] = $f[1] }
  }
  foreach ($line in [System.IO.File]::ReadLines($D_INFO)) {
    $f = $line.Split("`t")
    for ($i = 0; $i + 1 -lt $f.Count; $i += 2) {
      if ($f[$i] -eq "generated") { $script:DatasetGen = $f[$i + 1] }
      if ($f[$i] -eq "count") { $script:CveCount = [int]$f[$i + 1] }
    }
  }
}

# ======================================================================
# Facts Windows — parity collect_facts_windows()
# ======================================================================

function Get-WinFacts {
  # registry 64-bit view via .NET (parity winreg; hindari redirection PS 32-bit)
  $build = 0; $ubr = 0; $dver = ""; $product = ""; $edition = ""
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
      [Microsoft.Win32.RegistryHive]::LocalMachine,
      [Microsoft.Win32.RegistryView]::Registry64)
    $k = $base.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    if ($k) {
      $b = $k.GetValue("CurrentBuildNumber"); if ($b) { $build = [int]"$b" }
      $u = $k.GetValue("UBR");               if ($u) { $ubr = [int]"$u" }
      $dv = $k.GetValue("DisplayVersion");   if ($dv) { $dver = "$dv" }
      $pn = $k.GetValue("ProductName");      if ($pn) { $product = "$pn" }
      $ed = $k.GetValue("EditionID");        if ($ed) { $edition = "$ed" }
      $k.Close()
    }
    $base.Close()
  } catch { }
  if ($build -eq 0) {
    # fallback: Get-ItemProperty (view default proses) — parity fallback powershell python
    try {
      $p = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
      if ($p.CurrentBuildNumber) { $build = [int]"$($p.CurrentBuildNumber)" }
      if ($p.UBR) { $ubr = [int]"$($p.UBR)" }
      if ($p.DisplayVersion) { $dver = "$($p.DisplayVersion)" }
      if ($p.ProductName) { $product = "$($p.ProductName)" }
      if ($p.EditionID) { $edition = "$($p.EditionID)" }
    } catch { }
  }

  $fullBuild = ""
  if ($build -gt 0) { $fullBuild = "10.0.$build.$ubr" }

  # derive family + release tokens — parity ladder python
  $tokens = New-Object System.Collections.Generic.List[string]
  $fam = ""
  $prodL = $product.ToLowerInvariant()
  $isServer = $prodL.Contains("server")
  if ($build -gt 0) {
    if ($isServer) {
      $fam = "windows_server"
      if ($build -ge 26100)      { $tokens.Add("windows_server_2025") }
      elseif ($build -ge 25398)  { $tokens.Add("windows_server_2022_23h2") }
      elseif ($build -ge 20348)  { $tokens.Add("windows_server_2022") }
      elseif ($build -ge 17763)  { $tokens.Add("windows_server_2019") }
      elseif ($build -ge 14393)  { $tokens.Add("windows_server_2016") }
      elseif ($build -ge 9600)   { $tokens.Add("windows_server_2012_r2") }
      elseif ($build -ge 9200)   { $tokens.Add("windows_server_2012") }
      elseif ($build -ge 7601)   { $tokens.Add("windows_server_2008_r2") }
      else                       { $tokens.Add("windows_server_2008") }
    }
    elseif ($build -ge 26100) {
      $fam = "windows_11"
      $tokens.AddRange(@("windows_11_24h2", "windows_11_25h2", "windows_11_26h1"))
    }
    elseif ($build -ge 22000) {
      $fam = "windows_11"
      $rel = $dver.ToLowerInvariant()
      if ($script:WinRel.ContainsKey("windows_11")) {
        # iterasi urutan TSV (parity python: item terakhir dengan build sama yang menang)
        foreach ($r in $script:WinRelOrder["windows_11"]) {
          if ($script:WinRel["windows_11"][$r] -eq $build) { $rel = $r }
        }
      }
      if ($rel) { $tokens.Add("windows_11_$rel") } else { $tokens.Add("windows_11") }
    }
    elseif ($build -ge 10240) {
      $fam = "windows_10"
      $rel = $dver.ToLowerInvariant()
      if ($script:WinRel.ContainsKey("windows_10")) {
        foreach ($r in $script:WinRelOrder["windows_10"]) {
          if ($script:WinRel["windows_10"][$r] -eq $build) { $rel = $r }
        }
      }
      if ($rel) { $tokens.Add("windows_10_$rel") } else { $tokens.Add("windows_10") }
    }
    elseif ($build -ge 9600) { $fam = "windows_8.1"; $tokens.Add("windows_8.1") }
    elseif ($build -ge 7601) { $fam = "windows_7";   $tokens.Add("windows_7") }
  }
  if ($fam) { $tokens.Add($fam) }
  $tokens = @($tokens | Sort-Object -Unique)

  # hotfixes — parity: CIM dulu, fallback wmic (wmic hilang di Win11 24H2)
  $hotfixes = @()
  try {
    $hf = Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop |
          Select-Object -ExpandProperty HotFixID
    $hotfixes = @($hf | Where-Object { $_ -and "$_".Trim() -match "^KB\d+" } |
                  ForEach-Object { "$_".Trim() })
  } catch { $hotfixes = @() }
  if ($hotfixes.Count -eq 0) {
    try {
      $out = & cmd /c "wmic qfe get HotFixID 2>nul"
      if ($LASTEXITCODE -eq 0) {
        $hotfixes = @($out | Where-Object { "$_".Trim() -match "^KB\d+" } |
                      ForEach-Object { "$_".Trim() })
      }
    } catch { $hotfixes = @() }
  }

  # privileges token — parity regex (Se\w+Privilege), token name selalu Inggris
  $privileges = @()
  try {
    $out = (& whoami /priv 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) {
      $privileges = @([regex]::Matches($out, "Se[A-Za-z0-9_]+Privilege") |
                      ForEach-Object { $_.Value } | Sort-Object -Unique)
    }
  } catch { $privileges = @() }

  return @{
    hostname = [System.Net.Dns]::GetHostName()
    os       = "windows"
    arch     = $env:PROCESSOR_ARCHITECTURE
    windows  = @{
      product_name   = $product
      edition        = $edition
      display_version = $dver
      build          = $build
      ubr            = $ubr
      full_build     = $fullBuild
      release_tokens = $tokens
      hotfixes       = $hotfixes
      privileges     = $privileges
    }
    packages = @{}
    distro   = @{}
  }
}

# ======================================================================
# CVE matcher — tier os_build (windows), parity match_cves() python
# ======================================================================
$script:M_Tier = @{}; $script:M_Conf = @{}; $script:M_Rank = @{}
$script:M_Kev = @{}; $script:M_Esc = @{}; $script:M_Score = @{}
$script:M_Sev = @{}; $script:M_Pub = @{}; $script:M_Matches = @{}
$script:MatchIds = New-Object System.Collections.Generic.List[string]

function Get-TierRank([string]$tier) {
  switch ($tier) {
    "kernel"     { return 0 }
    "package"    { return 1 }
    "os_build"   { return 2 }
    "distro_pin" { return 3 }
    default      { return 9 }
  }
}

function Add-Match($id, [string]$tier, [string]$conf, [string]$cpe, [string]$raw,
                   [string]$installed, $kev, $esc, $score, $sev, $pub) {
  # parity _add_match python: rank lebih kecil menang; equal-tier high upgrade
  $kevB = ($kev -eq "1" -or $kev -eq $true)
  $escB = ($esc -eq "1" -or $esc -eq $true)
  $newRank = Get-TierRank $tier
  if ($script:M_Tier.ContainsKey($id)) {
    if ($newRank -lt $script:M_Rank[$id]) {
      # parity python: dict baru -> escape_class lama ikut terbuang
      $script:M_Tier[$id] = $tier; $script:M_Conf[$id] = $conf; $script:M_Rank[$id] = $newRank
      $script:M_Esc[$id] = $false
      $script:M_Matches[$id] = New-Object System.Collections.Generic.List[object]
    } elseif ($newRank -gt $script:M_Rank[$id]) {
      return
    } else {
      if ($conf -eq "high") { $script:M_Conf[$id] = "high" }
    }
    $script:M_Matches[$id].Add(@{ cpe = $cpe; constraint = $raw; installed = $installed })
    if ($escB) { $script:M_Esc[$id] = $true }
    return
  }
  $script:M_Tier[$id] = $tier; $script:M_Conf[$id] = $conf; $script:M_Rank[$id] = $newRank
  $script:M_Kev[$id] = $kevB; $script:M_Esc[$id] = $escB
  $script:M_Score[$id] = $score; $script:M_Sev[$id] = $sev; $script:M_Pub[$id] = $pub
  $script:M_Matches[$id] = New-Object System.Collections.Generic.List[object]
  $script:M_Matches[$id].Add(@{ cpe = $cpe; constraint = $raw; installed = $installed })
  [void]$script:MatchIds.Add($id)
}

function Get-EntryFam([string]$prod) {
  if ($prod.StartsWith("windows_server")) { return "windows_server" }
  foreach ($f in @("windows_11", "windows_10", "windows_8", "windows_7")) {
    if ($prod.StartsWith($f)) { return $f }
  }
  return $prod
}

function Match-Windows($facts) {
  $w = $facts["windows"]
  $tokens = @($w["release_tokens"])
  $buildNorm = @(Norm $w["full_build"])
  $tokenFams = @{}
  foreach ($t in $tokens) {
    if ($t.StartsWith("windows_server")) { $tokenFams["windows_server"] = $true }
    elseif ($t.StartsWith("windows_11")) { $tokenFams["windows_11"] = $true }
    elseif ($t.StartsWith("windows_10")) { $tokenFams["windows_10"] = $true }
    elseif ($t.StartsWith("windows_8"))  { $tokenFams["windows_8"] = $true }
    elseif ($t.StartsWith("windows_7"))  { $tokenFams["windows_7"] = $true }
  }
  foreach ($cpe in $script:CpeOrder) {
    $ci = $cpe.IndexOf(":")
    if ($ci -lt 0) { continue }
    $vend = $cpe.Substring(0, $ci); $prod = $cpe.Substring($ci + 1)
    if ($vend -ne "microsoft" -or -not $prod.StartsWith("windows_")) { continue }
    $efam = Get-EntryFam $prod
    if (-not $tokenFams.ContainsKey($efam) -and
        $efam -notin @("windows_10", "windows_11", "windows_server")) { continue }
    $famOk = $tokenFams.ContainsKey($efam)
    foreach ($row in $script:RowsByCpe[$cpe]) {
      $id = $row[0]; $pub = $row[1]; $score = $row[2]; $sev = $row[3]
      $kev = $row[4]; $esc = $row[5]; $raw = $row[8]
      if ($row[9] -eq "ALL") {
        # parity: fam ok + (kev ATAU product token persis terdeteksi)
        if ($famOk -and ($kev -eq "1" -or ($tokens -contains $prod))) {
          Add-Match $id "os_build" "possible" $cpe $raw $w["full_build"] $kev $esc $score $sev $pub
        }
        continue
      }
      if ($row[9] -eq "EXACT") {
        # release token [1607] / [20h2] / [sp1] -> build via ladder lpe-winrelease.tsv
        $rel = $row[10].ToLowerInvariant()
        if ($script:WinRel.ContainsKey($prod)) {
          $relmap = $script:WinRel[$prod]
          $b = $null
          if ($relmap.ContainsKey($rel)) { $b = $relmap[$rel] }
          elseif ($relmap.ContainsKey($rel.TrimStart("0"))) { $b = $relmap[$rel.TrimStart("0")] }
          if ($null -ne $b -and $b -eq $w["build"]) {
            Add-Match $id "os_build" "high" $cpe $raw $w["full_build"] $kev $esc $score $sev $pub
          }
        }
        continue
      }
      # bound build: product token harus tepat di tokens terdeteksi
      if (-not ($tokens -contains $prod)) { continue }
      if (EvalRow $row $buildNorm "n") {
        Add-Match $id "os_build" "high" $cpe $raw $w["full_build"] $kev $esc $score $sev $pub
      }
    }
  }
}

function Get-SortedIds {
  # parity sort python: (not kev, tier, -score, id)
  $props = @(
    @{ Expression = { if ($script:M_Kev[$_]) { 1 } else { 0 } } },
    @{ Expression = { $script:M_Rank[$_] } },
    @{ Expression = {
        if ($script:M_Score[$_] -and $script:M_Score[$_] -ne "-") { -[double]$script:M_Score[$_] }
        else { 0 } } },
    @{ Expression = { $_ } }
  )
  return @($script:MatchIds | Sort-Object -Property $props)
}

# ======================================================================
# ======================================================================
# PEAS checks — port 1:1 PEAS_CHECKS windows lpescan.py (10 cek)
# ======================================================================
$script:PeasFindings = New-Object System.Collections.Generic.List[object]

function Add-Peas($cat, $sev, $title, $detail, [string]$CheckOverride) {
  # detail: string ATAU array (array -> list JSON); check = nama pemanggil
  # (parity python run_peas: f["check"] = nama fungsi chk_*)
  $ck = if ($CheckOverride) { $CheckOverride } else { (Get-PSCallStack)[1].FunctionName }
  $script:PeasFindings.Add(@{
    category = $cat; severity = $sev; title = $title
    detail = $detail
    check = $ck
  })
}

function Run-Cmd([string]$cmdline) {
  # parity sh_out via cmd /c (reg query / sc / manage-bde — output stdout saja)
  try {
    return (cmd /c $cmdline 2>$null | Out-String)
  } catch { return "" }
}

function Test-AccessW([string]$path) {
  # parity os.access(path, os.W_OK|os.R_OK) di Windows (CPython win32_access):
  # keduanya = atribut ReadOnly tidak diset (GetFileAttributesW) — 100% read-only
  if ([string]::IsNullOrEmpty($path)) { return $false }
  try {
    $attr = [System.IO.File]::GetAttributes($path)
    return (($attr -band [System.IO.FileAttributes]::ReadOnly) -eq 0)
  } catch { return $false }
}

function chk_win_os($ctx) {
  $w = $ctx["facts"]["windows"]
  Add-Peas "os" "INFO" "OS" "$($w['product_name']) $($w['edition']) build $($w['full_build']) ($($w['display_version']))"
  $pod = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue |
         Select-Object -ExpandProperty PartOfDomain
  if ($null -ne $pod -and "$pod".ToLowerInvariant() -eq "false") {
    Add-Peas "os" "INFO" "workgroup (bukan domain)"
  }
  if ($env:COMPUTERNAME) { Add-Peas "os" "INFO" "COMPUTERNAME" "$env:COMPUTERNAME" }
  if ($env:USERNAME) { Add-Peas "os" "INFO" "USERNAME" "$env:USERNAME" }
}

function chk_win_hotfixes($ctx) {
  $hf = $ctx["facts"]["windows"]["hotfixes"]
  if ($hf.Count -gt 0) {
    $d20 = (@($hf | Select-Object -First 20)) -join ", "
    $d20 = $d20 + $(if ($hf.Count -gt 20) { "..." } else { "" })
    Add-Peas "hotfixes" "INFO" "$($hf.Count) hotfix terpasang" $d20
  } else {
    Add-Peas "hotfixes" "LOW" "daftar hotfix tidak terbaca (query gagal)"
  }
}

function chk_win_services($ctx) {
  $svc = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
           Select-Object Name, State, StartName, PathName)
  foreach ($s in $svc) {
    $pathRaw = "$($s.PathName)"
    if (-not $pathRaw) { continue }
    $p = $pathRaw.Trim().Trim('"')
    $nm = "$($s.Name)"; if (-not $nm) { $nm = "?" }
    $sm = "$($s.StartName)"; if (-not $sm) { $sm = "?" }
    # regex python diterapkan ke path MENTAH (dengan kutip): path berkutip tidak match
    if ($pathRaw.Trim() -match "^[A-Za-z]:\\[^`"']* [^`"']*$") {
      Add-Peas "services" "HIGH" "unquoted service path: $nm" $p
    }
    $d = Split-Path $p -Parent
    if ($d -and (Test-Path $d -PathType Container) -and (Test-AccessW $d)) {
      Add-Peas "services" "HIGH" "dir binary service writable: $d ($nm, StartName=$sm)"
    }
  }
}

function chk_win_alwaysinstalled($ctx) {
  foreach ($h in @("HKLM", "HKCU")) {
    foreach ($p in @("$h\SOFTWARE\Policies\Microsoft\Windows\Installer",
                     "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Installer")) {
      $out = Run-Cmd ('reg query "' + $p + '" /v AlwaysInstallElevated 2>nul')
      if ($out -and ($out -match "AlwaysInstallElevated\s+REG_DWORD\s+0x1")) {
        Add-Peas "registry" "HIGH" "AlwaysInstallElevated aktif di $h" "msi dengan payload → SYSTEM"
      }
    }
  }
}

function chk_win_privs($ctx) {
  foreach ($p in $ctx["facts"]["windows"]["privileges"]) {
    if ($script:WinPrivs.ContainsKey($p)) {
      Add-Peas "privileges" "HIGH" "token privilege: $p" "saran: $($script:WinPrivs[$p])"
    } else {
      Add-Peas "privileges" "INFO" "token privilege: $p"
    }
  }
}

function chk_win_creds($ctx) {
  $out = Run-Cmd "cmdkey /list"
  if ($out) {
    $tg = @([regex]::Matches($out, "Target:\s*(\S+)") |
            ForEach-Object { $_.Groups[1].Value })
    if ($tg.Count -gt 0) {
      Add-Peas "credentials" "MEDIUM" "stored credentials: $($tg.Count) target" `
        ((@($tg | Select-Object -First 10)) -join ", ")
    }
  }
  $out = Run-Cmd "vaultcmd /list"
  if ($out -and -not $out.Contains("Error") -and $out.Trim() -ne "") {
    $lines = @($out.Trim().Split([char]10) | ForEach-Object { $_.Trim() } |
               Select-Object -First 5)
    Add-Peas "credentials" "INFO" "credential vault ada" $lines
  }
  foreach ($f in @("C:\Windows\System32\config\SAM", "C:\Windows\System32\config\SYSTEM")) {
    if ((Test-Path $f) -and (Test-AccessW $f)) {
      Add-Peas "credentials" "HIGH" "$(Split-Path $f -Leaf) terbaca (secretsdump!)"
    }
  }
  foreach ($base in @("C:\Users", "C:\ProgramData")) {
    if (Test-Path $base -PathType Container) {
      foreach ($fn in @("unattend.xml", "sysprep.xml", "sysprep.inf")) {
        $found = @(Get-ChildItem $base -Recurse -Filter $fn -File -ErrorAction SilentlyContinue |
                   Select-Object -First 5)
        foreach ($m in $found) {
          $body = ""; $okRead = $true
          try { $body = [System.IO.File]::ReadAllText($m.FullName) } catch { $okRead = $false }
          if (-not $okRead) {
            Add-Peas "credentials" "MEDIUM" "file unattend: $($m.FullName)"
            continue
          }
          if ($body.Contains("<PlainText>true</PlainText>") -or $body.Contains("Password")) {
            Add-Peas "credentials" "HIGH" "unattend berisi password: $($m.FullName)"
          } else {
            Add-Peas "credentials" "MEDIUM" "file unattend: $($m.FullName)"
          }
        }
      }
    }
  }
  # gate Test-Path: parity glob python (return [] bila dir tidak ada) + hindari
  # binding param -File di provider non-FileSystem (mis. saat diuji di Linux)
  if (Test-Path "C:\Windows\Panther" -PathType Container) {
    $panther = @(Get-ChildItem "C:\Windows\Panther" -Filter "unattend*.xml" -File -ErrorAction SilentlyContinue)
    foreach ($m in $panther) { Add-Peas "credentials" "MEDIUM" "file unattend: $($m.FullName)" }
  }
  $gpp = @()
  if (Test-Path "C:\Windows\System32\GroupPolicy" -PathType Container) {
    $gpp = @(Get-ChildItem "C:\Windows\System32\GroupPolicy" -Recurse -Filter "Groups.xml" -File -ErrorAction SilentlyContinue)
  }
  foreach ($g in $gpp) {
    try {
      $body = [System.IO.File]::ReadAllText($g.FullName)
      if ($body.Contains("cpassword")) {
        Add-Peas "credentials" "HIGH" "GPP cpassword di $($g.FullName)" "dekripsi dengan gpp-decrypt"
      }
    } catch { }
  }
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
      [Microsoft.Win32.RegistryHive]::LocalMachine,
      [Microsoft.Win32.RegistryView]::Registry64)
    $k = $base.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
    if ($k) {
      foreach ($name in @("DefaultUserName", "DefaultPassword", "DefaultDomainName")) {
        try {
          $v = $k.GetValue($name)
          if ($v) {
            $sev = if ($name -eq "DefaultPassword") { "HIGH" } else { "MEDIUM" }
            Add-Peas "credentials" $sev "Winlogon $name terisi" "$v"
          }
        } catch { }
      }
      $k.Close()
    }
    $base.Close()
  } catch { }
}

function chk_win_uac($ctx) {
  $out = Run-Cmd 'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>nul'
  if ($out) {
    if ($out -match "EnableLUA\s+REG_DWORD\s+0x0") {
      Add-Peas "uac" "HIGH" "UAC dinonaktifkan (EnableLUA=0)"
    } else {
      Add-Peas "uac" "INFO" "UAC aktif"
    }
  }
  $out = Run-Cmd 'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin 2>nul'
  if ($out -and ($out -match "ConsentPromptBehaviorAdmin\s+REG_DWORD\s+0x0")) {
    Add-Peas "uac" "HIGH" "UAC auto-elevate admin (ConsentPromptBehaviorAdmin=0)"
  }
}

function chk_win_autoruns($ctx) {
  foreach ($h in @("HKLM", "HKCU")) {
    foreach ($key in @("SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
      $out = Run-Cmd ('reg query "' + $h + '\' + $key + '" 2>nul')
      if ($out) {
        foreach ($line in ($out -split "\r?\n")) {
          $m = [regex]::Match($line, "^\s+(\S+)\s+REG_\S+\s+(.+)$")
          if ($m.Success) {
            Add-Peas "autoruns" "MEDIUM" "autorun $h\${key}: $($m.Groups[1].Value)" `
              $m.Groups[2].Value.Trim()
          }
        }
      }
    }
  }
  if ($env:APPDATA) {
    $startup = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startup -PathType Container) {
      # foreach statement (bukan ForEach-Object) — parity check=fn.__name__ di Add-Peas
      foreach ($f in @(Get-ChildItem $startup -ErrorAction SilentlyContinue)) {
        Add-Peas "autoruns" "MEDIUM" "startup folder user: $($f.Name)"
      }
    }
  }
}

function chk_win_dll($ctx) {
  foreach ($ent in ("$env:PATH" -split ";")) {
    if ($ent -eq "" -or $ent -eq ".") {
      Add-Peas "dll" "HIGH" "PATH berisi '.' atau kosong"
      continue
    }
    if ((Test-Path $ent -PathType Container) -and (Test-AccessW $ent)) {
      Add-Peas "dll" "MEDIUM" "entri PATH writable: $ent"
    }
  }
  foreach ($base in @("C:\Program Files", "C:\Program Files (x86)")) {
    if (Test-Path $base -PathType Container) {
      # foreach statement (bukan ForEach-Object) — parity check=fn.__name__ di Add-Peas
      foreach ($d in @(Get-ChildItem $base -Directory -ErrorAction SilentlyContinue)) {
        if (Test-AccessW $d.FullName) {
          Add-Peas "dll" "MEDIUM" "dir di Program Files writable (DLL sideload): $($d.FullName)"
        }
      }
    }
  }
}

function chk_win_defense($ctx) {
  $names = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct `
             -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName)
  $names = @($names | Where-Object { $_ } | ForEach-Object { "$_".Trim() })
  if ($names.Count -gt 0) {
    Add-Peas "defense" "INFO" "AV terdeteksi" ($names -join ", ")
  } else {
    Add-Peas "defense" "LOW" "tidak ada AV terdeteksi (SecurityCenter2 kosong)"
  }
  if (Get-Command sc.exe -ErrorAction SilentlyContinue) {
    $out = sc.exe query windefend 2>$null | Out-String
    if ($LASTEXITCODE -eq 0 -and $out.Contains("RUNNING")) {
      Add-Peas "defense" "INFO" "Windows Defender berjalan"
    }
  }
  $out = Run-Cmd "manage-bde -status 2>nul"
  if ($out) {
    $m = [regex]::Match($out, "Conversion Status:\s*(\S+)")
    if ($m.Success) { Add-Peas "defense" "INFO" "BitLocker: $($m.Groups[1].Value)" }
  }
}

function Invoke-Peas($facts) {
  # parity run_peas(): urutan dekorator python, error per check -> F INFO "gagal"
  $script:PeasFindings = New-Object System.Collections.Generic.List[object]
  $ctx = @{ facts = $facts }
  $checks = @(
    @("chk_win_os", "os"), @("chk_win_hotfixes", "hotfixes"),
    @("chk_win_services", "services"), @("chk_win_alwaysinstalled", "registry"),
    @("chk_win_privs", "privileges"), @("chk_win_creds", "credentials"),
    @("chk_win_uac", "uac"), @("chk_win_autoruns", "autoruns"),
    @("chk_win_dll", "dll"), @("chk_win_defense", "defense")
  )
  foreach ($pair in $checks) {
    $name = $pair[0]; $cat = $pair[1]
    try {
      & $name $ctx
    } catch {
      Add-Peas $cat "INFO" "check $name gagal: $($_.Exception.Message)" "" $name
    }
  }
  return $script:PeasFindings
}

# ======================================================================
# Report JSON (hand-rolled, parity schema build_report python)
# ======================================================================

function Get-TargetJson($facts) {
  $w = $facts["windows"]
  $tokensJson = ($w["release_tokens"] | ForEach-Object { JStr $_ }) -join ","
  $hotfixJson = ($w["hotfixes"] | ForEach-Object { JStr $_ }) -join ","
  $privJson   = ($w["privileges"] | ForEach-Object { JStr $_ }) -join ","
  return '{' +
    '"hostname":' + (JStr $facts["hostname"]) +
    ',"os":"windows","arch":' + (JStr $facts["arch"]) + ',' +
    '"windows":{"product_name":' + (JStr $w["product_name"]) +
    ',"edition":' + (JStr $w["edition"]) +
    ',"display_version":' + (JStr $w["display_version"]) +
    ',"build":' + $w["build"] +
    ',"ubr":' + $w["ubr"] +
    ',"full_build":' + (JStr $w["full_build"]) +
    ',"release_tokens":[' + $tokensJson + ']' +
    ',"hotfixes":[' + $hotfixJson + ']' +
    ',"privileges":[' + $privJson + ']},' +
    '"packages":{},"distro":{}}'
}

function Get-PeasJson {
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append("  [")
  $first = $true
  foreach ($f in $script:PeasFindings) {
    if (-not $first) { [void]$sb.Append(",") } else { $first = $false }
    [void]$sb.Append("`n   {")
    [void]$sb.Append('"category":' + (JStr $f["category"]) + ',')
    [void]$sb.Append('"severity":' + (JStr $f["severity"]) + ',')
    [void]$sb.Append('"title":' + (JStr $f["title"]) + ',"detail":')
    $d = $f["detail"]
    if ($d -is [System.Array]) {
      $parts = @($d | ForEach-Object { JStr "$_" })
      [void]$sb.Append("[" + ($parts -join ",") + "]")
    } else {
      [void]$sb.Append((JStr "$d"))
    }
    [void]$sb.Append(',"check":' + (JStr $f["check"]) + '}')
  }
  [void]$sb.Append("]")
  return $sb.ToString()
}

function Get-CveFindingsJson {
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append("  [")
  $first = $true
  foreach ($id in (Get-SortedIds)) {
    if (-not $first) { [void]$sb.Append(",") } else { $first = $false }
    $kevJ = if ($script:M_Kev[$id]) { "true" } else { "false" }
    $escJ = if ($script:M_Esc[$id]) { "true" } else { "false" }
    [void]$sb.Append("`n   {")
    [void]$sb.Append('"id":' + (JStr $id) +
      ',"score":' + (JN $script:M_Score[$id]) +
      ',"severity":' + (JStrN $script:M_Sev[$id]) +
      ',"published":' + (JStrN $script:M_Pub[$id]) +
      ',"kev":' + $kevJ + ',')
    [void]$sb.Append('"matched_by":"' + $script:M_Tier[$id] +
      '","confidence":"' + $script:M_Conf[$id] +
      '","likely_backported":false,"escape_class":' + $escJ + ',')
    $mParts = @($script:M_Matches[$id] | ForEach-Object {
      '{"cpe":' + (JStr $_["cpe"]) +
      ',"constraint":' + (JStr $_["constraint"]) +
      ',"installed":' + (JStr $_["installed"]) + '}'
    })
    [void]$sb.Append('"matches":[' + ($mParts -join ",") + '],')
    $desc = ""
    if ($script:MetaById.ContainsKey($id)) { $desc = $script:MetaById[$id] }
    [void]$sb.Append('"description":' + (JStr $desc) + ',')
    if ($script:PocById.ContainsKey($id)) {
      $pParts = @($script:PocById[$id] | ForEach-Object {
        '{"repo":' + (JStr $_["repo"]) + ',"url":' + (JStr $_["url"]) + '}'
      })
      [void]$sb.Append('"has_poc":true,"pocs":[' + ($pParts -join ",") + ']}')
    } else {
      [void]$sb.Append('"has_poc":false,"pocs":[]}')
    }
  }
  [void]$sb.Append("]")
  return $sb.ToString()
}

function Get-StatsJson {
  $kevN = 0; $escN = 0; $kN = 0; $pN = 0; $obN = 0; $dN = 0
  $sevCount = @{}
  $sevOrder = New-Object System.Collections.Generic.List[string]
  foreach ($id in $script:MatchIds) {
    if ($script:M_Kev[$id]) { $kevN++ }
    if ($script:M_Esc[$id]) { $escN++ }
    switch ($script:M_Tier[$id]) {
      "kernel"     { $kN++ }
      "package"    { $pN++ }
      "os_build"   { $obN++ }
      "distro_pin" { $dN++ }
    }
    $s = "$($script:M_Sev[$id])"
    if ($s -eq "" -or $s -eq "-") { $s = "N/A" }
    if (-not $sevCount.ContainsKey($s)) { $sevCount[$s] = 0; [void]$sevOrder.Add($s) }
    $sevCount[$s]++
  }
  $sevParts = @($sevOrder | ForEach-Object { (JStr $_) + ":" + $sevCount[$_] })
  return '{"peas_total":' + $script:PeasFindings.Count +
    ',"cve_total":' + $script:MatchIds.Count +
    ',"kev":' + $kevN +
    ',"backport_flagged":0' +
    ',"escape_flagged":' + $escN +
    ',"by_tier":{"kernel":' + $kN + ',"package":' + $pN +
    ',"os_build":' + $obN + ',"distro_pin":' + $dN + '}' +
    ',"by_severity":{' + ($sevParts -join ",") + '}}'
}

function Write-Report($facts, [string]$outPath) {
  $dir = Split-Path $outPath -Parent
  if ($dir -and -not (Test-Path $dir)) {
    Write-Output "[!] direktori report tidak ada: $dir"
    exit 1
  }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('{
 "scanner":{"version":"' + $SCANNER_VERSION + '","impl":"' + $IMPL +
    '","dataset_generated":' + (JStr $script:DatasetGen) +
    ',"cve_count":' + $script:CveCount + '},
 "target":')
  [void]$sb.Append((Get-TargetJson $facts))
  [void]$sb.Append(',
 "findings":{"peas":')
  [void]$sb.Append((Get-PeasJson))
  [void]$sb.Append(',"cve":')
  [void]$sb.Append((Get-CveFindingsJson))
  [void]$sb.Append('},
 "stats":')
  [void]$sb.Append((Get-StatsJson))
  [void]$sb.Append("`n}`n")
  [System.IO.File]::WriteAllText($outPath, $sb.ToString(),
    (New-Object System.Text.UTF8Encoding($false)))
}

# ======================================================================
# Konsol — parity print_report() python (flavor windows)
# ======================================================================

function Show-Report($facts) {
  $w = $facts["windows"]
  Write-Output (Paint "================ LPESCAN ================" $C_B)
  Write-Output ((Paint " LPESCAN v" $C_B) + $SCANNER_VERSION + (Paint "  —  LPE scanner + CVE matcher" $C_B))
  Write-Output ((Paint " dataset: " $C_DIM) + $script:CveCount + " CVE (" + $script:DatasetGen + ")" + $C_R)
  Write-Output (Paint "================ LPESCAN ================" $C_B)
  Write-Output (Paint "[ TARGET ]" $C_B)
  Write-Output ("  hostname : " + $facts["hostname"] + "   os: " + $facts["os"] +
                "   arch: " + $facts["arch"])
  Write-Output ("  windows  : " + $w["product_name"] + " build " + $w["full_build"] +
                " (" + $w["display_version"] + ")")
  Write-Output ("  hotfixes : " + $w["hotfixes"].Count)

  $sorted = @(Get-SortedIds)
  $kevIds = @($sorted | Where-Object { $script:M_Kev[$_] })
  if ($kevIds.Count -gt 0) {
    Write-Output ""
    Write-Output (Paint "[ !!! ] $($kevIds.Count) CVE KEV (known exploited) TERDETEKSI !!!" $C_RB)
    foreach ($id in ($kevIds | Select-Object -First 10)) {
      $sv = $script:M_Sev[$id]; if ($sv -eq "-" -or -not $sv) { $sv = "?" }
      Write-Output ("  " + $id + " (" + $sv + " " + $script:M_Score[$id] + ") — " +
                    $script:M_Tier[$id])
    }
  }

  $byTier = @{}
  foreach ($id in $script:MatchIds) {
    $t = $script:M_Tier[$id]
    if (-not $byTier.ContainsKey($t)) { $byTier[$t] = 0 }
    $byTier[$t]++
  }
  $tierParts = @()
  foreach ($t in @("kernel", "package", "os_build", "distro_pin")) {
    if ($byTier.ContainsKey($t) -and $byTier[$t] -gt 0) { $tierParts += "$t=$($byTier[$t])" }
  }
  Write-Output ""
  Write-Output (Paint "[ CVE MATCH ] $($script:MatchIds.Count) CVE (by tier: $($tierParts -join ', '))" $C_B)
  Write-Output (Paint ("  {0,-18} {1,-9} {2,-4} {3,-10} {4,-28} {5}" -f
    "ID", "SEV", "KEV", "TIER", "KONSTRUKSI", "TERPASANG") $C_DIM)
  $shown = 0
  foreach ($id in $sorted) {
    if ($shown -ge 40) { break }
    $shown++
    $sev = $script:M_Sev[$id]; if ($sev -eq "-" -or -not $sev) { $sev = "?" }
    $sevCol = switch ($sev) {
      "CRITICAL" { $S_CRIT } "HIGH" { $S_HIGH } "MEDIUM" { $S_MED }
      "LOW" { $S_LOW } "INFO" { $S_INFO } default { $C_R }
    }
    $kevStr = if ($script:M_Kev[$id]) { "YES" } else { "" }
    $first = $script:M_Matches[$id][0]
    $cons = "$($first["constraint"])"; if ($cons.Length -gt 26) { $cons = $cons.Substring(0, 26) }
    $inst = "$($first["installed"])"; if ($inst.Length -gt 26) { $inst = $inst.Substring(0, 26) }
    $line = ("  {0,-18} {1} {2,-4} {3,-10} {4,-28} {5}" -f
      $id, (Paint ("{0,-9}" -f $sev) $sevCol), $kevStr, $script:M_Tier[$id], $cons, $inst)
    if ($script:PocById.ContainsKey($id)) { $line += (Paint "  [PoC]" $C_G) }
    if ($script:M_Esc[$id]) { $line += (Paint "  [ESC]" $C_M) }
    Write-Output $line
  }
  if ($script:MatchIds.Count -gt 40) {
    Write-Output (Paint ("  ... " + ($script:MatchIds.Count - 40) + " CVE lagi (lihat file report)") $C_DIM)
  }

  $escIds = @($sorted | Where-Object { $script:M_Esc[$_] })
  if ($escIds.Count -gt 0) {
    $ids8 = @($escIds | Select-Object -First 8)
    $suffix = if ($escIds.Count -gt 8) { " ..." } else { "" }
    Write-Output ""
    Write-Output (Paint "[ ! ] $($escIds.Count) match kelas container-escape (runc/containerd/kernel): $($ids8 -join ', ')$suffix" $C_MB)
    Write-Output (Paint "      target bukan container — relevan bila host ini menjalankan container" $C_DIM)
    Write-Output (Paint "      (runc/containerd/buildkit); di luar itu perlakukan sebagai LPE/DoS biasa." $C_DIM)
  }

  Write-Output ""
  Write-Output (Paint "[ PEAS CHECKS ] $($script:PeasFindings.Count) temuan" $C_B)
  $byCat = @{}
  $catOrder = New-Object System.Collections.Generic.List[string]
  foreach ($f in $script:PeasFindings) {
    if (-not $byCat.ContainsKey($f["category"])) {
      $byCat[$f["category"]] = New-Object System.Collections.Generic.List[object]
      [void]$catOrder.Add($f["category"])
    }
    $byCat[$f["category"]].Add($f)
  }
  foreach ($cat in $catOrder) {
    $fs = $byCat[$cat]
    Write-Output (Paint "  --- $cat ($($fs.Count)) ---" $C_B)
    $n = 0
    foreach ($f in $fs) {
      if ($n -ge 15) { break }
      $n++
      $sev = $f["severity"]
      $sevCol = switch ($sev) {
        "CRITICAL" { $S_CRIT } "HIGH" { $S_HIGH } "MEDIUM" { $S_MED }
        "LOW" { $S_LOW } "INFO" { $S_INFO } default { $C_R }
      }
      Write-Output ((Paint ("    [{0,-7}]" -f $sev) $sevCol) + " " + $f["title"])
      $d = $f["detail"]
      if ($d) {
        $dstr = if ($d -is [System.Array]) { ($d | ForEach-Object { "$_" }) -join " ; " } else { "$d" }
        if ($dstr.Length -gt 200) { $dstr = $dstr.Substring(0, 200) }
        Write-Output (Paint "      $dstr" $C_DIM)
      }
    }
    if ($fs.Count -gt 15) {
      Write-Output (Paint ("      ... " + ($fs.Count - 15) + " lagi (lihat file report)") $C_DIM)
    }
  }

  Write-Output ""
  Write-Output (Paint "[ ! ] Scanner hanya mendeteksi — TIDAK mengeksekusi PoC apa pun." $C_DIM)
  Write-Output (Paint "    Jalankan buildkit.py di mesin arsip untuk membundel biner yang cocok." $C_DIM)
}

# ======================================================================
# Selftest — version engine subset windows + flag escape + parse TSV
# ======================================================================
$script:ST_OK = 0
$script:ST_FAIL = 0

function Chk([string]$name, [bool]$cond, [string]$note = "") {
  if ($cond) {
    $script:ST_OK++
    Write-Output "  [OK]   $name"
  } else {
    $script:ST_FAIL++
    Write-Output "  [FAIL] $name  $note"
  }
}

function New-TestRow($id, $cpe, $raw, $op1, $v1, $n1, $op2, $v2, $n2, $op3, $v3, $n3,
                     $kev = "0", $esc = "0") {
  # 18 kolom, kolom absen = "-" (sentinel)
  return @($id, "2022-01-01", "7.0", "HIGH", $kev, $esc, "windows", $cpe, $raw,
           $op1, $v1, $n1, $op2, $v2, $n2, $op3, $v3, $n3)
}

function Invoke-Selftest {
  $script:ST_OK = 0; $script:ST_FAIL = 0

  Load-WinRelease   # ladder nyata utk tes (Load-Data penuh tidak dipanggil di selftest)

  Write-Output "[*] selftest version engine (PowerShell)..."
  Chk "toks 1.9.5p2" ((Toks "1.9.5p2") -join " " -eq "1 9 5 p 2")
  Chk "norm 5.15.0-72-generic" ((Norm "5.15.0-72-generic") -join " " -eq "5 15 0 72")
  Chk "norm buang trailing zero" ((Norm "6.8.0-generic") -join " " -eq "6 8")
  Chk "norm 20.04" ((Norm "20.04") -join " " -eq "20 4")
  Chk "norm kosong" ((Norm "") -join " " -eq "")
  Chk "cmp 1.6.3 < 1.6.3_p7" ((CmpV (Toks "1.6.3") (Toks "1.6.3_p7")) -eq -1)
  Chk "cmp 1.9.5 < 1.9.5p2" ((CmpV (Toks "1.9.5") (Toks "1.9.5p2")) -eq -1)
  Chk "cmp numerik 007 == 7" ((CmpV (Toks "007") (Toks "7")) -eq 0)
  Chk "cmp numeric > alpha" ((CmpV (Toks "1.9") (Toks "1.a")) -eq 1)

  $row = New-TestRow "T1" "microsoft:windows_11_23h2" "microsoft:windows_11_23h2 [<10.0.22631.4751]" `
    "<" "10.0.22631.4751" "10 0 22631 4751" "-" "-" "-" "-" "-" "-"
  Chk "build 22631.3447 match <4751" (EvalRow $row (Norm "10.0.22631.3447") "n")
  Chk "build 22631.4751 tidak match" (-not (EvalRow $row (Norm "10.0.22631.4751") "n"))
  $row = New-TestRow "T2" "microsoft:windows_10_22h2" "microsoft:windows_10_22h2 [>=10.0.19041 <10.0.22000]" `
    ">=" "10.0.19041" "10 0 19041" "<" "10.0.22000" "10 0 22000" "-" "-" "-"
  Chk "range 2-op: 19041.x match" (EvalRow $row (Norm "10.0.19041.1") "n")
  Chk "range 2-op: 22000 tidak match" (-not (EvalRow $row (Norm "10.0.22000") "n"))
  Chk "range 2-op: 17763 tidak match" (-not (EvalRow $row (Norm "10.0.17763") "n"))
  $row = New-TestRow "T3" "microsoft:windows_10_22h2" "microsoft:windows_10_22h2 [>=10.0.19041]" `
    ">=" "10.0.19041" "10 0 19041" "-" "-" "-" "-" "-" "-"
  Chk "range 1-op: 19045.5371 match" (EvalRow $row (Norm "10.0.19045.5371") "n")
  Chk "EXACT row + mode n" (EvalRow (New-TestRow "T4" "microsoft:windows_10" "microsoft:windows_10 [1607]" `
    "EXACT" "1607" "1607" "-" "-" "-" "-" "-" "-") (Norm "1607") "n")

  Write-Output "[*] selftest ladder release -> build..."
  $hasRel = (Test-Path $D_WINREL)
  if ($hasRel) {
    Chk "ladder windows_10 1607 -> 14393" ($script:WinRel["windows_10"]["1607"] -eq 14393)
    Chk "ladder windows_10 20h2 -> 19042" ($script:WinRel["windows_10"]["20h2"] -eq 19042)
    Chk "ladder windows_11 23h2 -> 22631" ($script:WinRel["windows_11"]["23h2"] -eq 22631)
    Chk "ladder windows_11 24h2/25h2/26h1 last-wins 26100" `
      ($script:WinRel["windows_11"]["24h2"] -eq 26100 -and
       $script:WinRel["windows_11"]["25h2"] -eq 26100 -and
       $script:WinRel["windows_11"]["26h1"] -eq 26100)
  } else {
    Write-Output "  [--]   lpe-winrelease.tsv tidak ada — tes ladder di-skip"
  }

  Write-Output "[*] selftest gating [all] + match tier windows (fake rows)..."
  # facts fake: Win11 23H2 22631.3447
  $fakeFacts = @{
    hostname = "TEST"; os = "windows"; arch = "AMD64"
    windows = @{
      product_name = "Windows 11 Pro"; edition = "Pro"; display_version = "23H2"
      build = 22631; ubr = 3447; full_build = "10.0.22631.3447"
      release_tokens = @("windows_11", "windows_11_23h2")
      hotfixes = @(); privileges = @()
    }
    packages = @{}; distro = @{}
  }
  $script:RowsByCpe = @{}
  $script:CpeOrder = New-Object System.Collections.Generic.List[string]
  $script:M_Tier = @{}; $script:M_Conf = @{}; $script:M_Rank = @{}
  $script:M_Kev = @{}; $script:M_Esc = @{}; $script:M_Score = @{}
  $script:M_Sev = @{}; $script:M_Pub = @{}; $script:M_Matches = @{}
  $script:MatchIds = New-Object System.Collections.Generic.List[string]
  $rAllKev = New-TestRow "CVE-T-ALLKEV" "microsoft:windows_11" "microsoft:windows_11 [all]" `
    "ALL" "-" "-" "-" "-" "-" "-" "-" "-" "1" "0"
  $rAllTok = New-TestRow "CVE-T-ALLTOK" "microsoft:windows_11_23h2" "microsoft:windows_11_23h2 [all]" `
    "ALL" "-" "-" "-" "-" "-" "-" "-" "-" "0" "1"
  $rAllSkip = New-TestRow "CVE-T-ALLSKIP" "microsoft:windows_11_22h2" "microsoft:windows_11_22h2 [all]" `
    "ALL" "-" "-" "-" "-" "-" "-" "-" "-" "0" "0"
  $rBound = New-TestRow "CVE-T-BOUND" "microsoft:windows_11_23h2" "microsoft:windows_11_23h2 [<10.0.22631.4751]" `
    "<" "10.0.22631.4751" "10 0 22631 4751" "-" "-" "-" "-" "-" "-" "0" "1"
  $rBoundFam = New-TestRow "CVE-T-BOUNDFAM" "microsoft:windows_11_22h2" "microsoft:windows_11_22h2 [<10.0.22621.4751]" `
    "<" "10.0.22621.4751" "10 0 22621 4751" "-" "-" "-" "-" "-" "-" "0" "0"
  # cpe EXACT di dataset nyata = kunci ladder (microsoft:windows_11), bukan token turunan
  $rExact = New-TestRow "CVE-T-EXACT" "microsoft:windows_11" "microsoft:windows_11 [23h2]" `
    "EXACT" "23h2" "-" "-" "-" "-" "-" "-" "-" "0" "0"
  $fakeCpes = @("microsoft:windows_11", "microsoft:windows_11_23h2",
                "microsoft:windows_11_22h2")
  foreach ($c in $fakeCpes) {
    $script:RowsByCpe[$c] = New-Object System.Collections.Generic.List[string[]]
    [void]$script:CpeOrder.Add($c)
  }
  $script:RowsByCpe["microsoft:windows_11"].Add($rAllKev)
  $script:RowsByCpe["microsoft:windows_11_23h2"].Add($rAllTok)
  $script:RowsByCpe["microsoft:windows_11_23h2"].Add($rBound)
  $script:RowsByCpe["microsoft:windows_11"].Add($rExact)
  $script:RowsByCpe["microsoft:windows_11_22h2"].Add($rAllSkip)
  $script:RowsByCpe["microsoft:windows_11_22h2"].Add($rBoundFam)
  $script:MetaById = @{}; $script:PocById = @{}
  Match-Windows $fakeFacts
  Chk "[all] kev -> possible (fam ok)" `
    ($script:M_Tier.ContainsKey("CVE-T-ALLKEV") -and $script:M_Conf["CVE-T-ALLKEV"] -eq "possible")
  Chk "[all] token persis -> possible" `
    ($script:M_Tier.ContainsKey("CVE-T-ALLTOK") -and $script:M_Conf["CVE-T-ALLTOK"] -eq "possible")
  Chk "[all] tanpa kev & token beda -> skip" (-not $script:M_Tier.ContainsKey("CVE-T-ALLSKIP"))
  Chk "bound build match -> high + escape_class" `
    ($script:M_Tier.ContainsKey("CVE-T-BOUND") -and $script:M_Conf["CVE-T-BOUND"] -eq "high" -and
     $script:M_Esc["CVE-T-BOUND"])
  Chk "bound build token beda -> skip" (-not $script:M_Tier.ContainsKey("CVE-T-BOUNDFAM"))
  Chk "EXACT release token match -> high" `
    ($script:M_Tier.ContainsKey("CVE-T-EXACT") -and $script:M_Conf["CVE-T-EXACT"] -eq "high")

  Write-Output "[*] selftest _add_match replace rules..."
  $script:M_Tier = @{}; $script:M_Conf = @{}; $script:M_Rank = @{}
  $script:M_Kev = @{}; $script:M_Esc = @{}; $script:M_Score = @{}
  $script:M_Sev = @{}; $script:M_Pub = @{}; $script:M_Matches = @{}
  $script:MatchIds = New-Object System.Collections.Generic.List[string]
  Add-Match "X" "distro_pin" "possible" "a:b" "[all]" "1.0" "0" "0" "5.0" "MEDIUM" "2020-01-01"
  Add-Match "X" "os_build" "high" "c:d" "[<2]" "1.5" "0" "1" "8.1" "HIGH" "2020-01-01"
  Chk "rank os_build < distro_pin -> replace" `
    ($script:M_Tier["X"] -eq "os_build" -and $script:M_Conf["X"] -eq "high" -and
     $script:M_Matches["X"].Count -eq 1 -and $script:M_Esc["X"])
  Add-Match "X" "os_build" "possible" "e:f" "[<3]" "1.5" "0" "0" "8.1" "HIGH" "2020-01-01"
  Chk "equal-tier append + high tetap" `
    ($script:M_Conf["X"] -eq "high" -and $script:M_Matches["X"].Count -eq 2)
  Add-Match "Y" "os_build" "possible" "g:h" "[all]" "2.0" "1" "0" "9.8" "CRITICAL" "2021-01-01"
  Add-Match "Y" "kernel" "high" "i:j" "[<3]" "2.0" "0" "0" "9.8" "CRITICAL" "2021-01-01"
  Chk "rank kernel < os_build -> replace" ($script:M_Tier["Y"] -eq "kernel")

  Write-Output "[*] selftest JSON escape..."
  Chk "JEsc \t\r\n" ((JEsc "a`tb`rc`n") -eq 'a\tb\rc\n')
  Chk "JEsc quote/backslash" ((JEsc 'a"b\c') -eq 'a\"b\\c')
  Chk "JEsc kontrol dibuang" ((JEsc "a`u{0001}b") -eq "ab")
  Chk "JEsc null" ((JEsc $null) -eq "")

  Write-Output "[*] selftest parse TSV nyata..."
  if (Test-Path $D_CVES_WIN) {
    $first = $null
    foreach ($line in [System.IO.File]::ReadLines($D_CVES_WIN)) {
      $first = $line; break
    }
    $f = $first.Split("`t")
    Chk "baris pertama 18 kolom" ($f.Count -eq 18)
    Chk "kolom id ^CVE-" ($f[0] -match "^CVE-")
    Chk "kolom cpe microsoft:windows_" ($f[7] -match "^microsoft:windows_")
    Chk "kolom n1 hanya digit+spasi" ($f[11] -match "^(\d+ )*\d+$")
  } else {
    Write-Output "  [--]   lpe-cves-win.tsv tidak ada — tes parse di-skip"
  }

  Write-Output ""
  Write-Output "[*] selftest selesai: $script:ST_OK OK, $script:ST_FAIL FAIL"
  return ($script:ST_FAIL -eq 0)
}

# ======================================================================
# Main
# ======================================================================

function Test-IsWindows {
  return ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
}

function Main {
  if ($Selftest) {
    # panggil sebagai statement polos (bukan kondisi/assign) agar outputnya ke konsol;
    # hasil dibaca dari counter script-scope yang diisi Chk
    Invoke-Selftest
    if ($script:ST_FAIL -eq 0) { exit 0 } else { exit 1 }
  }
  if (-not (Test-IsWindows)) {
    Write-Output "[!] lpescan.ps1 hanya untuk Windows — pakai lpescan.py atau lpescan.sh untuk Linux."
    exit 1
  }
  Load-Data
  if (-not $JsonOnly) {
    Write-Output "[*] dataset: $script:CveCount CVE ($script:DatasetGen) — impl $IMPL"
  }
  $facts = Get-WinFacts
  if (-not $JsonOnly) {
    Write-Output "[*] fakta target terkumpul (os=windows, build $($facts['windows']['full_build']))"
  }
  Match-Windows $facts
  if (-not $JsonOnly) {
    Write-Output "[*] CVE match: $($script:MatchIds.Count)"
  }
  [void](Invoke-Peas $facts)
  if (-not $JsonOnly) {
    Write-Output "[*] PEAS checks: $($script:PeasFindings.Count) temuan"
  }
  $ts = Get-Date -Format "yyyyMMdd-HHmmss"
  $outPath = $Report
  if (-not $outPath) { $outPath = "scan-report-$($facts['hostname'])-$ts.json" }
  Write-Report $facts $outPath
  if (-not $JsonOnly) {
    Show-Report $facts
    Write-Output ""
  }
  Write-Output "[+] report tersimpan: $outPath"
}

Main
