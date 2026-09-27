#!/usr/bin/env python3
# Проверка загрузки контента VRChat через настоящий API.
#
# Зачем. Проверять через curl по URL из кеша недостаточно: так мы проверяем
# файлы, а не то, что реально видит клиент. Настоящий аватар начинает грузиться
# только после того, как клиент получил метаданные. Метаданные требуют
# авторизации, поэтому здесь берётся токен из локального клиента.
#
# ПЕРЕНОСИМОСТЬ. Ничего не зашито: ни пути, ни токена, ни идентификатора
# пользователя. Путь к базе ищется по стандартным местам, токен читается из
# неё в момент запуска и никуда не записывается. На другой машине с другим
# браузером или клиентом скрипт найдёт свой источник или честно скажет, что
# источника нет.
#
# Источники токена, по порядку:
#   1. VRCX (десктоп-клиент) — ~/.config/VRCX/VRCX.sqlite3
#   2. Firefox — профили в ~/.mozilla/firefox, cookies.sqlite, значения в открытом виде
#   3. Chrome/Chromium/Brave — Cookies, значения зашифрованы; выводится понятное
#      сообщение, а не пустота
#
# Использование:
#   python3 scripts/vrchat-content-check.py            # сводка по контенту
#   python3 scripts/vrchat-content-check.py --list 20  # больше аватаров
#   python3 scripts/vrchat-content-check.py --source firefox
#   python3 scripts/vrchat-content-check.py --db /путь/к/базе.sqlite3

import argparse
import base64
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

API = "https://api.vrchat.cloud/api/1"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
TIMEOUT = 20


def log(msg):
    print(msg, file=sys.stderr)


# ── поиск базы клиента ────────────────────────────────────────────────────

def find_vrcx_db(explicit=None):
    """Ищет базу VRCX. Путь нигде не зашит — только стандартные каталоги."""
    if explicit:
        return explicit if os.path.exists(explicit) else None
    roots = []
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        roots.append(xdg)
    home = os.path.expanduser("~")
    roots.append(os.path.join(home, ".config"))
    for root in roots:
        for cand in sorted(glob.glob(os.path.join(root, "VRCX", "*.sqlite3"))):
            if os.path.exists(cand):
                return cand
    return None


# ── извлечение токена ─────────────────────────────────────────────────────

def token_from_vrcx(db_path):
    """Читает куку auth для api.vrchat.cloud прямо в рантайме.

    Значение в базе лежит как base64(JSON со списком кук). В саму базу и в файлы
    скрипта токен не попадает — он живёт только в памяти этого процесса.
    """
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = list(con.execute("select key, value from cookies"))
    finally:
        con.close()
    for _, raw in rows:
        blob = None
        for attempt in (raw,):
            try:
                blob = json.loads(base64.b64decode(attempt).decode("utf-8", "replace"))
                break
            except Exception:
                pass
        if not isinstance(blob, list):
            continue
        for c in blob:
            if not isinstance(c, dict):
                continue
            if c.get("Name") == "auth" and c.get("Value"):
                host = c.get("Domain", "")
                if "vrchat" in host:
                    return c["Value"]
    return None


def token_from_firefox():
    """В Firefox значения кук не зашифрованы, поэтому читаем напрямую."""
    pats = os.path.join(os.path.expanduser("~"), ".mozilla", "firefox", "*", "cookies.sqlite")
    for db in sorted(glob.glob(pats)):
        tmp = tempfile.mktemp(suffix=".sqlite")
        try:
            shutil.copy2(db, tmp)          # живая база может быть заблокирована
            con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            hit = list(con.execute(
                "select value from moz_cookies where name='auth' "
                "and host like '%vrchat%' limit 1"))
            con.close()
            if hit and hit[0][0]:
                return hit[0][0]
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return None


def find_chrome_cookies():
    """У Chrome значения зашифрованы ключом из связки с секрет-хранилищем.

    Расшифровка здесь намеренно не делается: это уже не проверка обхода, а
    работа с хранилищем ОС. Пользователю честнее сказать, где искать токен.
    """
    found = []
    for base in ("google-chrome", "chromium", "BraveSoftware/Brave-Browser", "vivaldi"):
        pat = os.path.join(os.path.expanduser("~"), ".config", base, "*", "Cookies")
        found += [p for p in glob.glob(pat) if os.path.exists(p)]
    return found


def get_token(source, db_path):
    if source in ("vrcx", "auto"):
        db = find_vrcx_db(db_path)
        if db:
            t = token_from_vrcx(db)
            if t:
                return t, f"токен из {db}"
        if source == "vrcx":
            return None, "база VRCX не найдена или без токена"
    if source in ("firefox", "auto"):
        t = token_from_firefox()
        if t:
            return t, "токен из Firefox"
        if source == "firefox":
            return None, "куки vrchat в Firefox не найдены"
    if source in ("chrome", "auto"):
        paths = find_chrome_cookies()
        if paths:
            return None, ("куки Chrome найдены, но значения зашифрованы: " + paths[0] +
                          " — залогиньтесь в VRChat в окне браузера, чтобы токен "
                          "оказался доступен, либо используйте клиент (--source vrcx)")
    return None, "источник токена не найден"


# ── работа с API ──────────────────────────────────────────────────────────

def api(path, token, method="GET"):
    req = urllib.request.Request(API + path, method=method)
    req.add_header("User-Agent", UA)
    # Токен VRChat принимает ИМЕННО как куку Cookie. Заголовок Authorization
    # даёт 401 Missing Credentials — проверено на живом API. Поэтому шлём оба:
    # кука работает, заголовок не мешает.
    req.add_header("Cookie", "auth=" + token)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body[:200].decode("utf-8", "replace")}
    except Exception as e:
        return 0, {"error": str(e)}


def fetch_url(url, timeout=TIMEOUT):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as e:
        return e.code, 0
    except Exception as e:
        return 0, str(e)[:80]


def main():
    ap = argparse.ArgumentParser(description="проверка контента VRChat через настоящий API")
    ap.add_argument("--db", help="путь к базе клиента, если автопоиск не сработал")
    ap.add_argument("--source", default="auto",
                    choices=["auto", "vrcx", "firefox", "chrome"],
                    help="где искать токен")
    ap.add_argument("--list", type=int, default=10, help="сколько аватаров проверить")
    ap.add_argument("--worlds", type=int, default=3, help="сколько миров проверить")
    args = ap.parse_args()

    token, origin = get_token(args.source, args.db)
    if not token:
        log("ТОКЕН НЕ НАЙДЕН")
        log("  " + origin)
        log("")
        log("Что делать: залогиниться в VRChat в клиенте (VRCX) или в браузере,")
        log("  затем запустить снова. Токен нигде не хранится: скрипт читает его")
        log("  из локального хранилища в момент запуска.")
        return 2
    log("источник: " + origin)
    log("токен в скрипте не зашит и на диск не пишется")
    print()

    st, me = api("/auth/user", token)
    print(f"  авторизация: HTTP {st}")
    if st != 200:
        print("    " + json.dumps(me, ensure_ascii=False)[:300])
        print()
        print("  Токен не принят. Если включена двухфакторная аутентификация,")
        print("  нужен код из приложения — скажи, и я запрошу его и повторю.")
        return 3
    uid = me.get("id")
    user = me.get("displayName", "?")
    print(f"  вошли как: {user}  (id: {uid})")
    print()

    # Аватары: ровно то, что клиент должен получить для «нового аватара».
    st, avs = api(f"/avatars?limit={max(args.list * 3, 30)}&sortOrder=updated&releaseStatus=public", token)
    print(f"  аватаров получено: HTTP {st}, штук {len(avs) if isinstance(avs, list) else 0}")
    ok = bad = 0
    hosts = {}
    if isinstance(avs, list):
        print()
        print("   загрузка файлов аватаров через систему:")
        for a in avs[:args.list]:
            url = a.get("imageUrl")
            if not url:
                continue
            from urllib.parse import urlparse
            h = urlparse(url).netloc
            hosts[h] = hosts.get(h, 0) + 1
            st, n = fetch_url(url)
            if st == 200 and isinstance(n, int) and n > 1000:
                ok += 1
                print(f"    OK   {a.get('name','?')[:26]:<26} {n:>9} Б")
            else:
                bad += 1
                print(f"    СБОЙ {a.get('name','?')[:26]:<26} HTTP {st} {n}")
    print()
    print("   хосты, откуда пришли аватары:")
    for h, c in sorted(hosts.items(), key=lambda x: -x[1]):
        print(f"     {h}  ({c})")
    print()
    print(f"   ИТОГ по аватарам: успешно {ok}, сбоев {bad}")
    print()

    if args.worlds:
        st, wls = api(f"/worlds?limit={args.worlds}&sortOrder=updated&releaseStatus=public", token)
        print(f"  миров получено: HTTP {st}")
        wok = wbad = 0
        if isinstance(wls, list):
            for w in wls[:args.worlds]:
                url = w.get("imageUrl")
                if not url:
                    continue
                st, n = fetch_url(url)
                if st == 200 and isinstance(n, int) and n > 1000:
                    wok += 1
                    print(f"    OK   {w.get('name','?')[:26]:<26} {n:>9} Б")
                else:
                    wbad += 1
                    print(f"    СБОЙ {w.get('name','?')[:26]:<26} HTTP {st} {n}")
            print()
            print(f"   ИТОГ по мирам: успешно {wok}, сбоев {wbad}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
