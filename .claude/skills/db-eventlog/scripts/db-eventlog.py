#!/usr/bin/env python3
# db-eventlog v1.0 — Журнал регистрации через ibcmd
# Source: https://github.com/Nikolay-Shirokov/cc-1c-skills

import argparse
import os
import re
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
IBCMD_OWNED_KEYS = ["--format", "--skip-root", "--from", "--to", "--follow", "--out"]

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


def normalize_date(value, param_name, default_time):
    """Формат ibcmd: YYYY-MM-DDThh:mm:ss[.mmmmmm]. Принимаем и «просто дату» — подставляем
    начало/конец суток, иначе платформа отвергнет значение молча."""
    if not value:
        return ""
    v = value.strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}$", v):
        return v + default_time
    if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{1,6})?$", v):
        return v.replace(" ", "T")
    print("Error: -%s '%s' is not a date; expected YYYY-MM-DD or "
          "YYYY-MM-DDThh:mm:ss[.mmmmmm]" % (param_name, value))
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Журнал регистрации через ibcmd")
    parser.add_argument("-Command", default="", choices=["", "export", "model"],
                        help="export (по умолчанию) | model (XSD модели событий)")
    parser.add_argument("-V8Path", default="",
                        help="Путь к ibcmd.exe (или каталог bin платформы)")
    parser.add_argument("-LogPath", default="",
                        help="Каталог журнала регистрации (позиционный параметр ibcmd)")
    parser.add_argument("-DataDir", default="",
                        help="Каталог данных сервера: журнал берётся из <DataDir>/log-data")
    parser.add_argument("-Format", default="", choices=["", "xml", "json"],
                        help="Формат выгрузки (по умолчанию у ibcmd — xml)")
    parser.add_argument("-From", default="", help="Начало периода")
    parser.add_argument("-To", default="", help="Конец периода")
    parser.add_argument("-Out", default="", help="Файл выгрузки (иначе — stdout)")
    parser.add_argument("-SkipRoot", action="store_true",
                        help="Пропустить корневой элемент: каждое событие — отдельная сущность")
    parser.add_argument("-Follow", type=int, default=None,
                        help="Частота ожидания новых событий, мс")
    parser.add_argument("-AdditionalIbcmdArguments", nargs="*", default=[],
                        help="Extra ibcmd arguments in --key=value form")
    known_opts = {s.lower() for a in parser._actions for s in a.option_strings}
    argv, v8_extra, ibcmd_extra = extract_extra_args(sys.argv[1:], known_opts)
    args = ci_parse_args(parser, argv)

    if v8_extra:
        print("Error: -AdditionalV8Arguments applies to 1cv8 only; this skill runs ibcmd")
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

    log_dir = args.LogPath
    if not log_dir and args.DataDir:
        log_dir = os.path.join(args.DataDir, "log-data")
        print("[note] log directory taken from -DataDir: %s" % log_dir)
    if not log_dir:
        print("Error: specify -LogPath <journal directory> or -DataDir <server data directory>")
        sys.exit(1)
    if not os.path.isdir(log_dir):
        print("Error: journal directory not found: %s" % log_dir)
        sys.exit(1)

    frm = normalize_date(args.From, "From", "T00:00:00")
    to = normalize_date(args.To, "To", "T23:59:59")
    if frm and to and frm >= to:
        print("Error: -From (%s) is not earlier than -To (%s)" % (frm, to))
        sys.exit(1)

    cmd = (args.Command or "export").lower()
    if cmd == "model":
        if not args.Out:
            print("Error: model export needs -Out <file.xsd>")
            sys.exit(1)
        arguments = ["eventlog", "model", "export", args.Out]
        target = args.Out
    else:
        arguments = ["eventlog", "export"]
        if args.Format:
            arguments.append("--format=%s" % args.Format)
        if args.SkipRoot:
            arguments.append("--skip-root")
        if frm:
            arguments.append("--from=%s" % frm)
        if to:
            arguments.append("--to=%s" % to)
        if args.Follow is not None:
            arguments.append("--follow=%s" % args.Follow)
        if args.Out:
            arguments.append("--out=%s" % args.Out)
        arguments.append(log_dir)
        target = args.Out

    arguments += extra
    out_dir = os.path.dirname(target) if target else ""
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    print("Running: ibcmd " + " ".join(format_args_for_display(arguments, "ibcmd")))
    r = run_ibcmd([ibcmd_exe] + arguments, has_username=True, warn_no_user=False)
    if r.returncode != 0:
        print("Error: ibcmd eventlog %s failed (code: %s)%s"
              % (cmd, r.returncode, describe_exit(r.returncode)))
        print_platform_output(r)
        sys.exit(r.returncode)

    # Постусловие: без -Out платформа пишет в stdout, и «успех» без вывода — ложный успех.
    if target:
        if not os.path.isfile(target):
            print("Error: exit code 0 but no file at %s — the event log was not exported" % target)
            sys.exit(1)
        size = os.path.getsize(target)
        if size <= 0:
            print("Error: exit code 0 but %s is empty — no events matched the filter" % target)
            sys.exit(2)
        print("Event log exported to: %s (%d bytes)" % (target, size))
    else:
        text = ((r.stdout or "") + (r.stderr or "")).rstrip()
        if not text:
            print("Error: exit code 0 but ibcmd produced no output — "
                  "no events matched the filter")
            sys.exit(2)
        print(text)
        print("--- End ---")


if __name__ == "__main__":
    main()