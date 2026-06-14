#!/usr/bin/env python3
import argparse
import datetime as dt
import getpass
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DB = DATA / "servers.db"
SECRETS = DATA / "secrets"
REPORTS = DATA / "reports"
EXPORTS = DATA / "exports"
ARCHIVES = DATA / "archives"


def now():
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def die(message, code=1):
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def ensure_dirs():
    for path in (DATA, SECRETS, REPORTS, EXPORTS, ARCHIVES):
        path.mkdir(parents=True, exist_ok=True)


def connect():
    ensure_dirs()
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = connect()
    conn.executescript(
        """
        create table if not exists servers (
            id text primary key,
            host text not null,
            user text not null default 'root',
            port integer not null default 22,
            tags text not null default '',
            note text not null default '',
            created_at text not null,
            updated_at text not null
        );

        create table if not exists reports (
            id integer primary key autoincrement,
            server_id text not null references servers(id) on delete cascade,
            path text not null,
            sha256 text not null,
            imported_at text not null
        );

        create table if not exists events (
            id integer primary key autoincrement,
            server_id text,
            kind text not null,
            detail text not null,
            created_at text not null
        );
        """
    )
    conn.commit()
    print(f"initialized {DB}")


def require_server(conn, server_id):
    row = conn.execute("select * from servers where id = ?", (server_id,)).fetchone()
    if row is None:
        die(f"server not found: {server_id}")
    return row


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def secret_path(server_id):
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in server_id)
    return SECRETS / f"{safe}.json.enc"


def passphrase(confirm=False):
    first = getpass.getpass("Vault passphrase: ")
    if not first:
        die("empty passphrase refused")
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            die("passphrases do not match")
    return first


def openssl_crypt(mode, src, dst, phrase):
    if mode not in ("-e", "-d"):
        die("invalid openssl mode")
    cmd = [
        "openssl",
        "enc",
        "-aes-256-cbc",
        "-pbkdf2",
        "-iter",
        "600000",
        "-salt",
        mode,
        "-in",
        str(src),
        "-out",
        str(dst),
        "-pass",
        "env:SERVER_VAULT_PASSPHRASE",
    ]
    env = os.environ.copy()
    env["SERVER_VAULT_PASSPHRASE"] = phrase
    proc = subprocess.run(cmd, env=env, text=True, capture_output=True)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        die(f"openssl failed: {detail}")


def load_secret_doc(server_id, phrase):
    path = secret_path(server_id)
    if not path.exists():
        return {"server_id": server_id, "updated_at": now(), "secrets": {}}
    with tempfile.TemporaryDirectory() as td:
        plain = Path(td) / "secrets.json"
        openssl_crypt("-d", path, plain, phrase)
        return json.loads(plain.read_text())


def save_secret_doc(server_id, doc, phrase):
    doc["server_id"] = server_id
    doc["updated_at"] = now()
    ensure_dirs()
    with tempfile.TemporaryDirectory() as td:
        plain = Path(td) / "secrets.json"
        enc = Path(td) / "secrets.json.enc"
        plain.write_text(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True))
        openssl_crypt("-e", plain, enc, phrase)
        shutil.copy2(enc, secret_path(server_id))


def add_event(conn, server_id, kind, detail):
    conn.execute(
        "insert into events(server_id, kind, detail, created_at) values (?, ?, ?, ?)",
        (server_id, kind, detail, now()),
    )
    conn.commit()


def cmd_add_server(args):
    conn = connect()
    ts = now()
    conn.execute(
        """
        insert into servers(id, host, user, port, tags, note, created_at, updated_at)
        values (?, ?, ?, ?, ?, ?, ?, ?)
        on conflict(id) do update set
            host = excluded.host,
            user = excluded.user,
            port = excluded.port,
            tags = excluded.tags,
            note = excluded.note,
            updated_at = excluded.updated_at
        """,
        (args.id, args.host, args.user, args.port, args.tags or "", args.note or "", ts, ts),
    )
    conn.commit()
    add_event(conn, args.id, "server.upsert", f"{args.user}@{args.host}:{args.port}")
    print(f"saved server {args.id}")


def cmd_list(_args):
    conn = connect()
    rows = conn.execute("select id, host, user, port, tags, updated_at from servers order by id").fetchall()
    if not rows:
        print("no servers")
        return
    for row in rows:
        print(f"{row['id']}\t{row['user']}@{row['host']}:{row['port']}\t{row['tags']}\t{row['updated_at']}")


def cmd_show(args):
    conn = connect()
    row = require_server(conn, args.server_id)
    reports = conn.execute(
        "select path, sha256, imported_at from reports where server_id = ? order by imported_at desc",
        (args.server_id,),
    ).fetchall()
    secret_exists = secret_path(args.server_id).exists()
    payload = dict(row)
    payload["has_encrypted_secrets"] = secret_exists
    payload["reports"] = [dict(r) for r in reports]
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_put_secret(args):
    conn = connect()
    require_server(conn, args.server_id)
    value = args.value if args.value is not None else getpass.getpass(f"Secret value for {args.key}: ")
    phrase = passphrase(confirm=not secret_path(args.server_id).exists())
    doc = load_secret_doc(args.server_id, phrase)
    doc.setdefault("secrets", {})[args.key] = value
    save_secret_doc(args.server_id, doc, phrase)
    add_event(conn, args.server_id, "secret.put", args.key)
    print(f"stored encrypted secret {args.key} for {args.server_id}")


def cmd_get_secret(args):
    conn = connect()
    require_server(conn, args.server_id)
    phrase = passphrase()
    doc = load_secret_doc(args.server_id, phrase)
    if args.key not in doc.get("secrets", {}):
        die(f"secret key not found: {args.key}")
    print(doc["secrets"][args.key])


def cmd_import_report(args):
    conn = connect()
    require_server(conn, args.server_id)
    src = Path(args.path).expanduser().resolve()
    if not src.is_file():
        die(f"report file not found: {src}")
    dest_dir = REPORTS / args.server_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = dest_dir / f"{stamp}-{src.name}"
    shutil.copy2(src, dest)
    digest = sha256_file(dest)
    rel = dest.relative_to(ROOT)
    conn.execute(
        "insert into reports(server_id, path, sha256, imported_at) values (?, ?, ?, ?)",
        (args.server_id, str(rel), digest, now()),
    )
    conn.commit()
    add_event(conn, args.server_id, "report.import", str(rel))
    print(f"imported report {rel}")


def cmd_export_agent(args):
    conn = connect()
    row = require_server(conn, args.server_id)
    reports = conn.execute(
        "select path, sha256, imported_at from reports where server_id = ? order by imported_at desc",
        (args.server_id,),
    ).fetchall()
    secret_keys = []
    if secret_path(args.server_id).exists() and args.include_secret_keys:
        phrase = passphrase()
        doc = load_secret_doc(args.server_id, phrase)
        secret_keys = sorted(doc.get("secrets", {}).keys())
    export = {
        "schema": "server-vault-agent-export/v1",
        "exported_at": now(),
        "server": {
            "id": row["id"],
            "host": row["host"],
            "user": row["user"],
            "port": row["port"],
            "tags": [t.strip() for t in row["tags"].split(",") if t.strip()],
            "note": row["note"],
        },
        "secret_policy": {
            "contains_secret_values": False,
            "secret_keys_available": secret_keys,
        },
        "reports": [dict(r) for r in reports],
        "agent_instructions": [
            "Use this export as context only.",
            "Do not expect secret values in this file.",
            "Ask the vault owner to retrieve needed secrets through server_vault.py get-secret.",
            "Write new findings back as a report and import it into the vault.",
        ],
    }
    EXPORTS.mkdir(parents=True, exist_ok=True)
    out = Path(args.out).expanduser().resolve() if args.out else EXPORTS / f"{args.server_id}-agent-export.json"
    out.write_text(json.dumps(export, indent=2, ensure_ascii=False))
    print(out)


def cmd_archive(args):
    ensure_dirs()
    phrase = passphrase(confirm=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = ARCHIVES / f"server-vault-{stamp}.tar.gz.enc"
    with tempfile.TemporaryDirectory() as td:
        tar_path = Path(td) / "server-vault.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(DATA, arcname="data", filter=lambda info: None if "/archives/" in info.name else info)
        openssl_crypt("-e", tar_path, archive, phrase)
    print(archive)


def build_parser():
    parser = argparse.ArgumentParser(description="Small encrypted server registry")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init")
    p.set_defaults(func=lambda args: init_db())

    p = sub.add_parser("add-server")
    p.add_argument("--id", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--user", default="root")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--tags", default="")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_add_server)

    p = sub.add_parser("list")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show")
    p.add_argument("server_id")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("put-secret")
    p.add_argument("server_id")
    p.add_argument("--key", required=True)
    p.add_argument("--value")
    p.set_defaults(func=cmd_put_secret)

    p = sub.add_parser("get-secret")
    p.add_argument("server_id")
    p.add_argument("--key", required=True)
    p.set_defaults(func=cmd_get_secret)

    p = sub.add_parser("import-report")
    p.add_argument("server_id")
    p.add_argument("path")
    p.set_defaults(func=cmd_import_report)

    p = sub.add_parser("export-agent")
    p.add_argument("server_id")
    p.add_argument("--out")
    p.add_argument("--include-secret-keys", action="store_true")
    p.set_defaults(func=cmd_export_agent)

    p = sub.add_parser("archive")
    p.set_defaults(func=cmd_archive)

    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
