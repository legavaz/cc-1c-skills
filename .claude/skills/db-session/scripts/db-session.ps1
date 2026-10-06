# db-session v1.0 — Сеансы и блокировки автономного сервера через ibcmd
# Source: https://github.com/Nikolay-Shirokov/cc-1c-skills
# NB: *nix-раскладку платформы (/opt/1cv8/<ver>/1cv8, без .exe) знает только .py-порт — PS на *nix не исполняется.
<#
.SYNOPSIS
    Сеансы информационной базы и её блокировки (ibcmd)

.DESCRIPTION
    list      — список сеансов (опционально с лицензиями)
    info      — сведения о сеансе по его идентификатору
    terminate — принудительное завершение сеанса
    interrupt — прерывание текущего серверного вызова сеанса
    locks     — блокировки информационной базы (опционально по сеансу)

    ВАЖНО: режимы session/lock у ibcmd работают ТОЛЬКО с РАБОТАЮЩИМ автономным сервером
    (ibsrv.exe) и подключаются к нему через --pid (эта же машина) или --remote (шлюз
    администрирования на другой машине). Параметры подключения к базе (--db-path, --data,
    реквизиты пользователя) эти режимы НЕ принимают — в offline-режиме сеансов и блокировок
    просто не существует, поэтому и спросить их нельзя.

.EXAMPLE
    .\db-session.ps1 -Command list -ProcessId 1234

.EXAMPLE
    .\db-session.ps1 -Command terminate -ProcessId 1234 -Session 8f2e...-... -ErrorMessage "Работа завершена"

.EXAMPLE
    .\db-session.ps1 -Command locks -Remote http://srv:8315
#>

[CmdletBinding(PositionalBinding=$false)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("", "list", "info", "terminate", "interrupt", "locks")]
    [string]$Command = "list",

    # Идентификатор процесса РАБОТАЮЩЕГО автономного сервера на этой же машине.
    [Parameter(Mandatory=$false)]
    [string]$ProcessId,

    # Сетевой адрес шлюза администрирования автономного сервера на другой машине.
    [Parameter(Mandatory=$false)]
    [string]$Remote,

    [Parameter(Mandatory=$false)]
    [string]$Session,

    [Parameter(Mandatory=$false)]
    [string]$ErrorMessage,

    [Parameter(Mandatory=$false)]
    [switch]$Licenses,

    [Parameter(Mandatory=$false)]
    [string]$V8Path,

    [Parameter(Mandatory=$false)]
    [string[]]$AdditionalIbcmdArguments = @()
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
trap { Write-Host "Error: $($_.Exception.Message) ($($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber))" -ForegroundColor Red; exit 1 }

# --- Параметры, которыми навык управляет сам ---
$script:IbcmdOwnedKeys = @(
    '--pid', '--remote', '--session', '--error-message', '--licenses'
)

function Test-ArgKeyMatch {
    param([string]$Token, [string]$Key)
    if ($Token.Length -lt $Key.Length) { return $false }
    if (-not $Token.Substring(0, $Key.Length).Equals($Key, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Token.Length -eq $Key.Length) { return $true }
    return -not [char]::IsLetter($Token[$Key.Length])
}

function Resolve-IbcmdPath {
    param([string]$V8PathArg)
    if ($V8PathArg) {
        if (Test-Path -LiteralPath $V8PathArg -PathType Leaf) {
            if ((Split-Path $V8PathArg -Leaf) -notmatch '^ibcmd') {
                Write-Host "Error: this skill runs ibcmd only, but -V8Path points to '$(Split-Path $V8PathArg -Leaf)'; pass ibcmd.exe" -ForegroundColor Red
                exit 1
            }
            return (Resolve-Path -LiteralPath $V8PathArg).Path
        }
        $binDir = $V8PathArg
    } else {
        $binDir = 'C:\Program Files\1cv8'
    }
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

function ConvertFrom-IbcmdRecords {
    # Вывод ibcmd: строки «ключ : значение», записи разделены пустой строкой.
    param([string]$Text)
    $records = @()
    $cur = [ordered]@{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($cur.Count -gt 0) { $records += ,$cur; $cur = [ordered]@{} }
            continue
        }
        $idx = $line.IndexOf(':')
        if ($idx -lt 1) { continue }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim().Trim('"')
        if (-not $key) { continue }
        if ($cur.Contains($key)) { $records += ,$cur; $cur = [ordered]@{} }
        $cur[$key] = $val
    }
    if ($cur.Count -gt 0) { $records += ,$cur }
    return $records
}

function Write-Table {
    param([string[]]$Headers, $Rows)
    $widths = @()
    foreach ($h in $Headers) { $widths += $h.Length }
    foreach ($r in $Rows) {
        for ($i = 0; $i -lt $Headers.Count; $i++) {
            $len = ([string]$r[$i]).Length
            if ($len -gt $widths[$i]) { $widths[$i] = $len }
        }
    }
    $line = '  '
    for ($i = 0; $i -lt $Headers.Count; $i++) { $line += $Headers[$i].PadRight($widths[$i] + 2) }
    Write-Host $line.TrimEnd() -ForegroundColor Cyan
    foreach ($r in $Rows) {
        $line = '  '
        for ($i = 0; $i -lt $Headers.Count; $i++) { $line += ([string]$r[$i]).PadRight($widths[$i] + 2) }
        Write-Host $line.TrimEnd()
    }
}

# --- Подключение: работающий автономный сервер ---
# Ни --db-path, ни --data режимы session/lock не принимают, поэтому и спрашивать базу нельзя.
if (-not $ProcessId -and -not $Remote) {
    Write-Host "Error: specify -ProcessId <ibsrv.exe process id> or -Remote <gateway url>" -ForegroundColor Red
    Write-Host "  Session and lock modes work only against a RUNNING standalone server; see docs/ibcmd/." -ForegroundColor Red
    exit 1
}
if ($ProcessId -and $Remote) {
    Write-Host "Error: -ProcessId and -Remote are mutually exclusive - the server is either local or remote" -ForegroundColor Red
    exit 1
}
if ($ProcessId -and $ProcessId -notmatch '^\d+$') {
    Write-Host "Error: -ProcessId must be a process id (digits), got '$ProcessId'" -ForegroundColor Red
    exit 1
}
if ($ProcessId) {
    $proc = Get-Process -Id ([int]$ProcessId) -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Host "Error: no process with id $ProcessId - start ibsrv.exe first or pass -Remote" -ForegroundColor Red
        exit 1
    }
    if ($proc.ProcessName -ne 'ibsrv') {
        Write-Host "Error: process $ProcessId is '$($proc.ProcessName)', not ibsrv — session/lock modes need the standalone server" -ForegroundColor Red
        exit 1
    }
}

# --- Проверка команды ---
$needsSession = @('info', 'terminate', 'interrupt')
if ($needsSession -contains $Command -and -not $Session) {
    Write-Host "Error: $Command needs -Session <uuid>" -ForegroundColor Red
    exit 1
}
if ($ErrorMessage -and ($Command -ne 'terminate' -and $Command -ne 'interrupt')) {
    Write-Host "Error: -ErrorMessage applies to terminate and interrupt only (got '$Command')" -ForegroundColor Red
    exit 1
}
if ($Licenses -and ($Command -ne 'list' -and $Command -ne 'info')) {
    Write-Host "Error: -Licenses applies to list and info only (got '$Command')" -ForegroundColor Red
    exit 1
}

# --- Дополнительные аргументы ibcmd ---
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

$ibcmdExe = Resolve-IbcmdPath $V8Path

# --- Построение команды ---
switch ($Command) {
    'list' {
        $arguments = @("session", "list")
        if ($Licenses) { $arguments += "--licenses" }
    }
    'info' {
        $arguments = @("session", "info", "--session=$Session")
        if ($Licenses) { $arguments += "--licenses" }
    }
    'terminate' {
        $arguments = @("session", "terminate", "--session=$Session")
        if ($ErrorMessage) { $arguments += "--error-message=$ErrorMessage" }
    }
    'interrupt' {
        $arguments = @("session", "interrupt-current-server-call", "--session=$Session")
        if ($ErrorMessage) { $arguments += "--error-message=$ErrorMessage" }
    }
    'locks' {
        $arguments = @("lock", "list")
        if ($Session) { $arguments += "--session=$Session" }
    }
}
if ($ProcessId) { $arguments += "--pid=$ProcessId" } else { $arguments += "--remote=$Remote" }
$arguments += $extraArgs

Write-Host "Running: ibcmd $($arguments -join ' ')"
$result = Invoke-PlatformProcess $ibcmdExe $arguments
$exitCode = $result.ExitCode

if ($exitCode -ne 0) {
    Write-Host "Error: ibcmd session $Command failed (code: $exitCode)" -ForegroundColor Red
    Write-Host $result.Output
    Write-Host "--- End ---" -ForegroundColor Red
    exit $exitCode
}

# --- Разбор вывода ---
# session list печатает таблицу колонок, session info/lock list — записи «ключ : значение».
$text = $result.Output.Trim()
# @( ) обязателен: функция возвращает массив записей, а PowerShell разворачивает массив из
# одного элемента в сам словарь — тогда .Count посчитал бы КЛЮЧИ записи, а не записи.
$records = @(ConvertFrom-IbcmdRecords $text)
switch ($Command) {
    'list' {
        $target = if ($ProcessId) { "pid=$ProcessId" } else { "remote=$Remote" }
        if (-not $text) {
            Write-Host "[СЕАНСЫ] $target" -ForegroundColor Green
            Write-Host "  активных сеансов нет" -ForegroundColor Yellow
            exit 0
        }
        # session list печатает готовую таблицу колонок — перепечатываем как есть.
        Write-Host "[СЕАНСЫ] $target" -ForegroundColor Green
        Write-Host $text
    }
    'info' {
        if ($records.Count -eq 0) {
            Write-Host "Error: the platform returned no properties for session $Session" -ForegroundColor Red
            Write-Host $text
            exit 1
        }
        $rows = @()
        foreach ($rec in $records) {
            foreach ($k in $rec.Keys) { $rows += ,@($k, $rec[$k]) }
        }
        Write-Host "[СЕАНС] $Session" -ForegroundColor Green
        Write-Table @('Свойство', 'Значение') $rows
    }
    'locks' {
        if ($records.Count -eq 0) {
            Write-Host "  блокировок нет" -ForegroundColor Yellow
            exit 0
        }
        $rows = @()
        foreach ($rec in $records) {
            $rows += ,@($rec['connection'], $rec['session'], $rec['object'], $rec['locked'], $rec['descr'])
        }
        Write-Host "[БЛОКИРОВКИ] $($records.Count)" -ForegroundColor Green
        Write-Table @('Соединение', 'Сессия', 'Объект', 'С момента', 'Описание') $rows
    }
    default {
        Write-Host "[ГОТОВО] $Command выполнена для сеанса $Session" -ForegroundColor Green
        if ($text) {
            Write-Host $text
            Write-Host "--- End ---"
        }
    }
}
exit 0
