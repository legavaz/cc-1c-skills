# db-eventlog v1.0 — Журнал регистрации через ibcmd
# Source: https://github.com/Nikolay-Shirokov/cc-1c-skills
# NB: *nix-раскладку платформы (/opt/1cv8/<ver>/1cv8, без .exe) знает только .py-порт — PS на *nix не исполняется.
<#
.SYNOPSIS
    Выгрузка журнала регистрации утилитой ibcmd

.DESCRIPTION
    Навык работает ТОЛЬКО движком ibcmd (режим eventlog). Ключевое отличие от остальных навыков
    семейства db-*: ibcmd читает не информационную базу, а КАТАЛОГ ЖУРНАЛА РЕГИСТРАЦИИ
    (позиционный параметр <path> команды eventlog export — путь к каталогу журнала, обычно
    <каталог данных сервера>\log-data).

    model — выгрузка XSD-схемы модели событий журнала (ibcmd eventlog model export).

.EXAMPLE
    .\db-eventlog.ps1 -V8Path "C:\Program Files\1cv8\8.3.27.2214\bin\ibcmd.exe" -LogPath "C:\srv\log-data" -From 2026-09-25 -To 2026-09-26

.EXAMPLE
    .\db-eventlog.ps1 -V8Path "C:\Program Files\1cv8\8.3.27.2214\bin\ibcmd.exe" -LogPath "C:\srv\log-data" -Format json -Out "C:\WS\events.json"
#>

[CmdletBinding(PositionalBinding=$false)]
param(
    # Не Mandatory: обязательный параметр PowerShell запрашивает интерактивно, а в пакетном
    # запуске это зависание. Пустое значение проверяем сами.
    [Parameter(Mandatory=$false)]
    [string]$Command,

    [Parameter(Mandatory=$false)]
    [string]$V8Path,

    # Каталог журнала регистрации (позиционный параметр ibcmd eventlog export).
    [Parameter(Mandatory=$false)]
    [string]$LogPath,

    # Каталог данных сервера: из него берётся log-data, когда -LogPath не задан.
    [Parameter(Mandatory=$false)]
    [string]$DataDir,

    [Parameter(Mandatory=$false)]
    [ValidateSet("xml", "json")]
    [string]$Format = "",

    [Parameter(Mandatory=$false)]
    [string]$From,

    [Parameter(Mandatory=$false)]
    [string]$To,

    [Parameter(Mandatory=$false)]
    [string]$Out,

    [Parameter(Mandatory=$false)]
    [switch]$SkipRoot,

    [Parameter(Mandatory=$false)]
    [int]$Follow,

    [Parameter(Mandatory=$false)]
    [string[]]$AdditionalIbcmdArguments = @()
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
trap { Write-Host "Error: $($_.Exception.Message) ($($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber))" -ForegroundColor Red; exit 1 }

# --- Параметры, которыми навык управляет сам: через -AdditionalIbcmdArguments их не задают ---
# Иначе параметр продублируется в командной строке, и значение навыка перестанет быть
# единственным источником правды (ibcmd трактует повтор как второй источник, а не как замену).
$script:IbcmdOwnedKeys = @(
    '--format', '--skip-root', '--from', '--to', '--follow', '--out'
)

function Test-ArgKeyMatch {
    # A token matches a key when it equals the key, or starts with it and the next
    # character is not a letter — catches glued /N"user" and --password=x, while
    # keeping /ClearCache distinct from /C.
    param([string]$Token, [string]$Key)
    if ($Token.Length -lt $Key.Length) { return $false }
    if (-not $Token.Substring(0, $Key.Length).Equals($Key, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Token.Length -eq $Key.Length) { return $true }
    return -not [char]::IsLetter($Token[$Key.Length])
}

function Resolve-IbcmdPath {
    # ibcmd не на всех установках платформы; путь ищем рядом с 1cv8 и по умолчанию по v8path.
    param([string]$V8PathArg)
    $binDir = $null
    if ($V8PathArg) {
        if (Test-Path -LiteralPath $V8PathArg -PathType Leaf) {
            if ((Split-Path $V8PathArg -Leaf) -notmatch '^ibcmd') {
                Write-Host "Error: this skill runs ibcmd only, but -V8Path points to '$(Split-Path $V8PathArg -Leaf)'; pass ibcmd.exe" -ForegroundColor Red
                exit 1
            }
            return (Resolve-Path -LiteralPath $V8PathArg).Path
        }
        $binDir = $V8PathArg
    }
    if (-not $binDir) { $binDir = 'C:\Program Files\1cv8' }
    $candidates = @(Get-ChildItem -Path $binDir -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending |
                    ForEach-Object { Join-Path $_.FullName 'bin\ibcmd.exe' })
    $candidates += @(Join-Path $binDir 'ibcmd.exe')
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c -PathType Leaf) { return $c }
    }
    Write-Host "Error: ibcmd.exe not found (looked in: $($candidates -join '; ')). This platform install does not include ibcmd" -ForegroundColor Red
    exit 1
}

function ConvertFrom-PlatformBytes {
    # ibcmd writes UTF-8 (checked on 8.3.24, 8.3.27, 8.5), a crashing 1cv8 may still emit
    # OEM text. Decode strictly as UTF-8 and fall back to cp866 on invalid bytes — guessing
    # one of them outright mangles Cyrillic.
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    try {
        $strict = New-Object System.Text.UTF8Encoding($false, $true)
        return $strict.GetString($Bytes)
    } catch {
        return [System.Text.Encoding]::GetEncoding(866).GetString($Bytes)
    }
}

function Invoke-PlatformProcess {
    # Run the platform non-interactively and capture its console output. A closed stdin pipe
    # (EOF) makes an auth prompt fast-fail instead of hanging; capturing keeps the child's
    # text out of our stream until we print it labelled (and out of the wrong encoding).
    # Returns @{ Output; ExitCode }.
    #
    # Quoting differs by engine, so the caller says which it built:
    #   ibcmd    — tokens are bare (--db-path=C:\a b), the whole token gets quoted here;
    #   1cv8     — -PreQuoted: the caller already put quotes inside the token (File="C:\a b"),
    #              which is where 1C's own parser expects them; quoting again breaks the value.
    param([string]$Exe, [string[]]$ProcArgs, [switch]$PreQuoted)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = if ($PreQuoted) {
        $ProcArgs -join ' '
    } else {
        ($ProcArgs | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    # stderr is drained in parallel: reading the streams one after another deadlocks
    # as soon as the other one fills its pipe buffer.
    $errMs = New-Object System.IO.MemoryStream
    $errTask = $p.StandardError.BaseStream.CopyToAsync($errMs)
    $outMs = New-Object System.IO.MemoryStream
    $p.StandardOutput.BaseStream.CopyTo($outMs)
    $errTask.Wait()
    $p.WaitForExit()
    $out = ConvertFrom-PlatformBytes $outMs.ToArray()
    $err = ConvertFrom-PlatformBytes $errMs.ToArray()
    if ($err) { $out += $err }
    return [pscustomobject]@{ Output = $out; ExitCode = $p.ExitCode }
}

# --- Разбор команды ---
# export — действие по умолчанию: выгрузка журнала нужна почти всегда, model (XSD) — редко.
$knownCommands = @('export', 'model')
$cmd = if ($Command) { $Command.Trim().ToLower() } else { 'export' }
if ($knownCommands -notcontains $cmd) {
    Write-Host "Error: unknown command '$Command' (expected: $($knownCommands -join ' | '))" -ForegroundColor Red
    exit 1
}

# --- Дополнительные аргументы ibcmd ---
# argparse в .py не понимает значения, начинающиеся с '-', поэтому там ключи вытаскиваются
# отдельным проходом; здесь -AdditionalIbcmdArguments и так массив.
$extraArgs = @()
foreach ($tok in $AdditionalIbcmdArguments) {
    foreach ($piece in ([string]$tok -split ',')) {
        $t = $piece.Trim()
        if (-not $t) { continue }
        if (-not $t.StartsWith('-')) {
            Write-Host "Error: '$t' is a positional token - pass values as --key=value (-AdditionalIbcmdArguments cannot extend the ibcmd command)" -ForegroundColor Red
            exit 1
        }
        $dup = $false
        foreach ($k in $script:IbcmdOwnedKeys) {
            if (Test-ArgKeyMatch $t $k) { $dup = $true; break }
        }
        if ($dup) {
            Write-Host "Error: '$t' is managed by the skill itself; remove it from -AdditionalIbcmdArguments" -ForegroundColor Red
            exit 1
        }
        $extraArgs += $t
    }
}

# --- Разрешение пути ibcmd ---
$ibcmdExe = Resolve-IbcmdPath $V8Path

# --- Каталог журнала ---
# eventlog export читает каталог журнала, а не базу; -DataDir — короткий путь к log-data.
$logDir = $LogPath
if (-not $logDir -and $DataDir) {
    $logDir = Join-Path $DataDir 'log-data'
    Write-Host "[note] log directory taken from -DataDir: $logDir" -ForegroundColor Yellow
}
if (-not $logDir) {
    Write-Host "Error: specify -LogPath <journal directory> or -DataDir <server data directory>" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -LiteralPath $logDir -PathType Container)) {
    Write-Host "Error: journal directory not found: $logDir" -ForegroundColor Red
    exit 1
}

# --- Проверка диапазона дат ---
# Формат ibcmd: YYYY-MM-DDThh:mm:ss[.mmmmmm]. Принимаем и «просто дату» — подставляем начало суток,
# иначе платформа отвергнет значение молча, а выгрузка молча вернёт не тот период.
function Normalize-Date([string]$Value, [string]$ParamName, [string]$DefaultTime) {
    if (-not $Value) { return '' }
    $v = $Value.Trim()
    if ($v -match '^\d{4}-\d{2}-\d{2}$') { return "$v$DefaultTime" }
    if ($v -match '^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{1,6})?$') {
        return ($v -replace ' ', 'T')
    }
    Write-Host "Error: -$ParamName '$Value' is not a date; expected YYYY-MM-DD or YYYY-MM-DDThh:mm:ss[.mmmmmm]" -ForegroundColor Red
    exit 1
}

$from = Normalize-Date $From 'From' 'T00:00:00'
$to = Normalize-Date $To 'To' 'T23:59:59'
if ($from -and $to -and $from -ge $to) {
    Write-Host "Error: -From ($from) is not earlier than -To ($to)" -ForegroundColor Red
    exit 1
}

# --- Построение команды ---
if ($cmd -eq 'model') {
    # XSD-схема модели событий: навык отдаёт её отдельным файлом (stdout нечитаем).
    if (-not $Out) {
        Write-Host "Error: model export needs -Out <file.xsd>" -ForegroundColor Red
        exit 1
    }
    $arguments = @("eventlog", "model", "export", "$Out")
    $extraOut = $Out
} else {
    $arguments = @("eventlog", "export")
    if ($Format) { $arguments += "--format=$Format" }
    if ($SkipRoot) { $arguments += "--skip-root" }
    if ($from) { $arguments += "--from=$from" }
    if ($to) { $arguments += "--to=$to" }
    if ($PSBoundParameters.ContainsKey('Follow')) { $arguments += "--follow=$Follow" }
    if ($Out) { $arguments += "--out=$Out" }
    $arguments += "$logDir"
    $extraOut = $Out
}
$arguments += $extraArgs

$outDir = if ($extraOut) { Split-Path $extraOut -Parent } else { '' }
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

Write-Host "Running: ibcmd $($arguments -join ' ')"
$result = Invoke-PlatformProcess $ibcmdExe $arguments
$exitCode = $result.ExitCode

if ($exitCode -eq 0) {
    # Постусловие: без -Out платформа пишет в stdout, и «успех» без вывода — ложный успех.
    if ($extraOut) {
        if (-not (Test-Path -LiteralPath $extraOut -PathType Leaf)) {
            Write-Host "Error: exit code 0 but no file at $extraOut — the event log was not exported" -ForegroundColor Red
            exit 1
        }
        $len = (Get-Item -LiteralPath $extraOut).Length
        if ($len -le 0) {
            Write-Host "Error: exit code 0 but $extraOut is empty — no events matched the filter" -ForegroundColor Yellow
            exit 2
        }
        Write-Host "Event log exported to: $extraOut ($len bytes)" -ForegroundColor Green
    } elseif (-not $result.Output) {
        Write-Host "Error: exit code 0 but ibcmd produced no output — no events matched the filter" -ForegroundColor Yellow
        exit 2
    } else {
        Write-Host $result.Output
        Write-Host "--- End ---" -ForegroundColor Green
    }
} else {
    Write-Host "Error: ibcmd eventlog $cmd failed (code: $exitCode)" -ForegroundColor Red
    Write-Host $result.Output
    Write-Host "--- End ---" -ForegroundColor Red
    exit $exitCode
}
exit 0
