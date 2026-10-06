#!/usr/bin/env python3
# db-session v1.0 — Сеансы и блокировки автономного сервера через ibcmd
# Source: https://github.com/Nikolay-Shirokov/cc-1c-skills

import argparse
import os
import subprocess
import sys

# Общий блок группы db-*: реквизиты хранилища, дополнительные аргументы, запуск платформы.
# Копии держит одинаковыми tests/skills/check-inline-drift.mjs — правку вносить в навык-эталон.

V8_SECRET_KEYS = ["/P", "/UC", "/WSP", "/AWSP", "/ConfigurationRepositoryP"]
IBCMD_SECRET_KEYS = ["--password", "--token", "--db-pwd"]
IBCMD_NOUSER_HINT = (
    "[ibcmd] No -UserName/-Password given; the infobase may require authentication. "
    "On Windows ibcmd reads credentials from the console (stdin is ignored), so this "
    "call may block instead of failing. If it does not return promptly, abort and "
    "re-run with -UserName and -Password.\n"
)

# Параметры, которыми навык управляет сам: через -AdditionalIbcmdArguments их не задают.
IBCMD_OWNED_KEYS = ["--pid", "--remote", "--session", "--error-message", "--licenses"]

def ci_parse_args(parser, argv=None):
    """parse_args по правилам PS: имена параметров и значения choices регистронезависимы."""
    argv = list(sys.argv[1:] if argv is None else argv)
    names = {s.lower(): s for a in parser._actions for s in a.option_strings}
    for i, tok in enumerate(argv):
        if tok.startswith('-') and tok.lower() in names:
            argv[i] = names[tok.lower()]
    # choices — зеркало [ValidateSet]; канонизируем ДО разбора, иначе argparse отвергнет регистр
    choice_map = {}
    for a in parser._actions:
        if a.choices:
            for s in a.option_strings:
                choice_map[s] = {str(c).lower(): c for c in a.choices}
    for i in range(len(argv) - 1):
        m = choice_map.get(argv[i])
        if m and argv[i + 1].lower() in m:
            argv[i + 1] = m[argv[i + 1].lower()]
    return parser.parse_args(argv)


def arg_key_match(token, key):
    """Token matches a key when it equals it, or starts with it and the next character
    is not a letter — catches glued /N"user" and --password=x, while keeping
    /ClearCache distinct from /C."""
    if len(token) < len(key):
        return False
    if token[: len(key)].lower() != key.lower():
        return False
    if len(token) == len(key):
        return True
    return not token[len(key)].isalpha()


def format_args_for_display(arglist, engine):
    """Redact values of secret-prone keys in glued, =-joined and separate forms.
    Matching here is a plain prefix (no letter rule): over-masking costs nothing,
    a leaked password does."""
    keys = IBCMD_SECRET_KEYS if engine == "ibcmd" else V8_SECRET_KEYS
    res = []
    mask_next = False
    for tok in arglist:
        if mask_next:
            res.append("***")
            mask_next = False
            continue
        hit = None
        for k in keys:
            if tok[: len(k)].lower() == k.lower():
                hit = k
                break
        if hit is None:
            res.append(tok)
        elif len(tok) == len(hit):
            res.append(tok)
            mask_next = True
        elif tok[len(hit)] == "=":
            res.append(hit + "=***")
        else:
            res.append(hit + "***")
    return res


def extract_extra_args(argv, known_opts):
    """argparse refuses values that start with '-' (every ibcmd key does), so pull the two
    escape-hatch lists out of argv by hand: after the flag, take everything up to the next
    declared skill option. Returns (remaining_argv, v8_extra, ibcmd_extra)."""
    rest, v8, ibcmd = [], [], []
    i = 0
    while i < len(argv):
        low = argv[i].lower()
        if low in ("-additionalv8arguments", "-additionalibcmdarguments"):
            target = v8 if low == "-additionalv8arguments" else ibcmd
            i += 1
            while i < len(argv) and argv[i].lower() not in known_opts:
                target.append(argv[i])
                i += 1
            continue
        rest.append(argv[i])
        i += 1
    return rest, v8, ibcmd

def decode_platform_bytes(data):
    """ibcmd writes UTF-8 (checked on 8.3.24, 8.3.27, 8.5), a crashing 1cv8 may still emit
    OEM text. Decode strictly as UTF-8 and fall back to cp866 on invalid bytes — the locale
    code page (what text=True uses) mangles both."""
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp866", errors="replace")


def print_platform_output(result):
    """Print what the platform wrote to the console as its own labelled block. Silence stays
    silent: in batch mode 1cv8 reports through /Out and prints nothing here."""
    text = ((result.stdout or "") + (result.stderr or "")).rstrip()
    if not text:
        return
    limit = 65536
    if len(text) > limit:
        text = f"[... обрезано, показаны последние {limit} символов ...]\n" + text[-limit:]
    print("--- Вывод платформы ---")
    print(text)
    print("--- End ---")

def run_ibcmd(cmd, has_username=False, warn_no_user=True):
    """Run an ibcmd command non-interactively.

    input="" closes stdin (EOF) so ibcmd's auth prompt fast-fails instead of hanging.
    On Windows without -UserName ibcmd reads the console directly and may still block —
    that residual case is flagged via IBCMD_NOUSER_HINT (model-facing).
    """
    if warn_no_user and os.name == "nt" and not has_username:
        sys.stdout.write(IBCMD_NOUSER_HINT)
        sys.stderr.flush()
    r = subprocess.run(cmd, input=b"", capture_output=True)
    r.stdout = decode_platform_bytes(r.stdout)
    r.stderr = decode_platform_bytes(r.stderr)
    return r


def describe_exit(code):
    """Annotate an abnormal process exit code so a crash isn't reported as a bare number.
    Batch 1C in a broken/headless environment (no GUI session, no license) can crash mid-run
    instead of returning a clean error, possibly leaving the infobase locked or half-mutated."""
    if code is None:
        return ""
    win = {
        3221225477: "0xC0000005 (access violation)", -1073741819: "0xC0000005 (access violation)",
        3221225781: "0xC0000135 (missing DLL)", -1073741515: "0xC0000135 (missing DLL)",
        3221226505: "0xC0000409 (stack overrun)", -1073740791: "0xC0000409 (stack overrun)",
    }
    if code in win:
        return f" — abnormal termination, exception {win[code]}; the infobase may be left in an inconsistent state; verify it before retrying"
    if -64 <= code < 0:
        try:
            import signal
            name = signal.Signals(-code).name
        except (ValueError, AttributeError):
            name = f"signal {-code}"
        return (f" — process terminated by {name} (abnormal termination, not a normal exit); "
                "the infobase may be left in an inconsistent state; verify it before retrying")
    return ""


def _redact(text, *secrets):
    """Redact literal secret values (password, user) from a display string —
    precise, never touches lookalike paths."""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


def resolve_ibcmd_path(v8path):
    """ibcmd есть не в каждой установке платформы. Путь берём из -V8Path, иначе ищем рядом
    с 1cv8 (каталог bin или старший каталог версии), иначе — типовые места установки."""
    suffix = ".exe" if os.name == "nt" else ""
    if v8path:
        if os.path.isfile(v8path):
            if not os.path.basename(v8path).lower().startswith("ibcmd"):
                print("Error: this skill runs ibcmd only, but -V8Path points to '%s'; "
                      "pass ibcmd.exe" % os.path.basename(v8path))
                sys.exit(1)
            return os.path.abspath(v8path)
        bin_dir = v8path
    else:
        bin_dir = None
    roots = []
    if bin_dir:
        roots.append(bin_dir)
    if os.name == "nt":
        roots.append(r"C:\Program Files\1cv8")
        roots.append(r"C:\Program Files (x86)\1cv8")
    else:
        roots.append("/opt/1cv8")
    for root in roots:
        if not os.path.isdir(root):
            continue
        if os.path.isfile(os.path.join(root, "ibcmd" + suffix)):
            return os.path.join(root, "ibcmd" + suffix)
        try:
            versions = sorted((d for d in os.listdir(root)
                               if os.path.isdir(os.path.join(root, d, "bin"))),
                              reverse=True)
        except OSError:
            continue
        for v in versions:
            cand = os.path.join(root, v, "bin", "ibcmd" + suffix)
            if os.path.isfile(cand):
                return cand
    print("Error: ibcmd%s not found in: %s. This platform install does not include ibcmd"
          % (suffix, ", ".join(roots)))
    sys.exit(1)


def parse_ibcmd_records(text):
    """Вывод ibcmd: строки «ключ : значение», записи разделены пустой строкой."""
    records, cur = [], {}
    for line in (text or "").splitlines():
        if not line.strip():
            if cur:
                records.append(cur)
                cur = {}
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip().strip('"')
        if not key:
            continue
        if key in cur:
            records.append(cur)
            cur = {}
        cur[key] = val
    if cur:
        records.append(cur)
    return records


def write_table(headers, rows):
    if not rows:
        return
    widths = [len(h) for h in headers]
    for r in rows:
        for i, h in enumerate(headers):
            widths[i] = max(widths[i], len(str(r[i])))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    for r in rows:
        print("  ".join(str(r[i]).ljust(widths[i]) for i in range(len(headers))))


def process_alive(pid):
    """Проверка, что процесс существует. На *nix os.kill(pid, 0) — проба без сигнала."""
    try:
        if os.name == "nt":
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Сеансы информационной базы и её блокировки (ibcmd)")
    parser.add_argument("-Command", default="list",
                        choices=["list", "info", "terminate", "interrupt", "locks"])
    parser.add_argument("-ProcessId", default="",
                        help="Process id of a RUNNING ibsrv.exe on this machine")
    parser.add_argument("-Remote", default="",
                        help="Administration gateway URL of a standalone server")
    parser.add_argument("-Session", default="", help="Session uuid")
    parser.add_argument("-ErrorMessage", default="", help="Причина завершения/прерывания")
    parser.add_argument("-Licenses", action="store_true",
                        help="Вывести сведения о лицензиях сеанса (list, info)")
    parser.add_argument("-V8Path", default="",
                        help="Путь к ibcmd.exe (или каталог bin платформы)")
    parser.add_argument("-AdditionalIbcmdArguments", nargs="*", default=[],
                        help="Extra ibcmd arguments in --key=value form")
    known_opts = {s.lower() for a in parser._actions for s in a.option_strings}
    argv, v8_extra, ibcmd_extra = extract_extra_args(sys.argv[1:], known_opts)
    args = ci_parse_args(parser, argv)

    if v8_extra:
        print("Error: -AdditionalV8Arguments applies to 1cv8 only; this skill runs ibcmd")
        sys.exit(1)

    # Подключение: только работающий автономный сервер. Режимы session/lock не принимают
    # --db-path/--data — в offline-режиме сеансов и блокировок не существует вовсе.
    cmd = args.Command
    if not args.ProcessId and not args.Remote:
        print("Error: specify -ProcessId <ibsrv.exe process id> or -Remote <gateway url>")
        print("  Session and lock modes work only against a RUNNING standalone server; "
              "see docs/ibcmd/.")
        sys.exit(1)
    if args.ProcessId and args.Remote:
        print("Error: -ProcessId and -Remote are mutually exclusive - the server is "
              "either local or remote")
        sys.exit(1)
    if args.ProcessId:
        if not args.ProcessId.strip().isdigit():
            print("Error: -ProcessId must be a process id (digits), got '%s'" % args.ProcessId)
            sys.exit(1)
        if not process_alive(int(args.ProcessId)):
            print("Error: no process with id %s - start ibsrv.exe first or pass -Remote"
                  % args.ProcessId)
            sys.exit(1)

    if cmd in ("info", "terminate", "interrupt") and not args.Session:
        print("Error: %s needs -Session <uuid>" % cmd)
        sys.exit(1)
    if args.ErrorMessage and cmd not in ("terminate", "interrupt"):
        print("Error: -ErrorMessage applies to terminate and interrupt only (got '%s')" % cmd)
        sys.exit(1)
    if args.Licenses and cmd not in ("list", "info"):
        print("Error: -Licenses applies to list and info only (got '%s')" % cmd)
        sys.exit(1)

    extra = []
    for tok in ibcmd_extra:
        for piece in str(tok).split(","):
            t = piece.strip()
            if not t:
                continue
            if not t.startswith("-"):
                print("Error: '%s' is a positional token - pass values as --key=value "
                      "(-AdditionalIbcmdArguments cannot extend the ibcmd command)" % t)
                sys.exit(1)
            for k in IBCMD_OWNED_KEYS:
                if arg_key_match(t, k):
                    print("Error: '%s' is managed by the skill itself; remove it from "
                          "-AdditionalIbcmdArguments" % t)
                    sys.exit(1)
            extra.append(t)

    ibcmd_exe = resolve_ibcmd_path(args.V8Path)

    if cmd == "list":
        arguments = ["session", "list"]
        if args.Licenses:
            arguments.append("--licenses")
    elif cmd == "info":
        arguments = ["session", "info", "--session=%s" % args.Session]
        if args.Licenses:
            arguments.append("--licenses")
    elif cmd == "terminate":
        arguments = ["session", "terminate", "--session=%s" % args.Session]
        if args.ErrorMessage:
            arguments.append("--error-message=%s" % args.ErrorMessage)
    elif cmd == "interrupt":
        arguments = ["session", "interrupt-current-server-call", "--session=%s" % args.Session]
        if args.ErrorMessage:
            arguments.append("--error-message=%s" % args.ErrorMessage)
    else:
        arguments = ["lock", "list"]
        if args.Session:
            arguments.append("--session=%s" % args.Session)

    if args.ProcessId:
        arguments.append("--pid=%s" % args.ProcessId)
    else:
        arguments.append("--remote=%s" % args.Remote)
    arguments += extra

    print("Running: ibcmd " + " ".join(format_args_for_display(arguments, "ibcmd")))
    r = run_ibcmd([ibcmd_exe] + arguments, has_username=True, warn_no_user=False)
    text = ((r.stdout or "") + (r.stderr or "")).strip()
    if r.returncode != 0:
        print("Error: ibcmd session %s failed (code: %s)%s"
              % (cmd, r.returncode, describe_exit(r.returncode)))
        print_platform_output(r)
        sys.exit(r.returncode)

    target = "pid=%s" % args.ProcessId if args.ProcessId else "remote=%s" % args.Remote
    if cmd == "list":
        if not text:
            print("[СЕАНСЫ] %s" % target)
            print("  активных сеансов нет")
            return
        print("[СЕАНСЫ] %s" % target)
        print(text)
    elif cmd == "info":
        records = parse_ibcmd_records(text)
        if not records:
            print("Error: the platform returned no properties for session %s" % args.Session)
            print(text)
            sys.exit(1)
        rows = []
        for rec in records:
            for k, v in rec.items():
                rows.append([k, v])
        print("[СЕАНС] %s" % args.Session)
        write_table(["Свойство", "Значение"], rows)
    elif cmd == "locks":
        records = parse_ibcmd_records(text)
        if not records:
            print("  блокировок нет")
            return
        rows = [[r.get("connection", ""), r.get("session", ""), r.get("object", ""),
                 r.get("locked", ""), r.get("descr", "")] for r in records]
        print("[БЛОКИРОВКИ] %d" % len(records))
        write_table(["Соединение", "Сессия", "Объект", "С момента", "Описание"], rows)
    else:
        print("[ГОТОВО] %s выполнена для сеанса %s" % (cmd, args.Session))
        if text:
            print(text)
            print("--- End ---")


if __name__ == "__main__":
    main()