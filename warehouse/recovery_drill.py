"""Opt-in local SQL backup and disposable restore; default is read-only status.

Run from the repo root with Windows authentication:
    .venv\\Scripts\\python.exe -m warehouse.recovery_drill --run

This is same-instance database recovery proof, not whole-PC or Wazuh recovery.
Private backup data never belongs in the repository or public evidence.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import uuid

import pyodbc

from warehouse.apply_sql import CONN_STR


SOURCE = "SentinelGridWarehouse"
ROOT = Path.home() / ".watchtide-private" / "recovery"
DIRECTORY_HELPER = Path(__file__).with_name("Prepare-RecoveryDirectory.ps1")


def identifier(value):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value):
        raise ValueError("Unsafe SQL identifier")
    return f"[{value}]"


def restore_name(value):
    if not re.fullmatch(r"WatchtideRestore_[0-9a-f]{32}", value):
        raise ValueError("Only a disposable recovery database is allowed")
    return identifier(value)


def literal(value):
    if "\x00" in value:
        raise ValueError("NUL is not allowed in SQL literals")
    return "N'" + value.replace("'", "''") + "'"


def operation(conn, sql, *params, reject_rows=False):
    cur = conn.cursor()
    try:
        cur.execute(sql, *params)
        errors = 0
        while True:
            if cur.description:
                errors += len(cur.fetchall())
            if not cur.nextset():
                break
        if reject_rows and errors:
            raise RuntimeError("Database integrity check reported errors")
    finally:
        cur.close()


def rows(conn, sql, *params):
    cur = conn.cursor()
    try:
        cur.execute(sql, *params)
        fields = [field[0] for field in cur.description]
        return [dict(zip(fields, row)) for row in cur.fetchall()]
    finally:
        cur.close()


def source_state(conn, database=SOURCE):
    if database != SOURCE and not re.fullmatch(r"WatchtideRecoveryTest_[0-9a-f]{32}", database):
        raise ValueError("Source is not the warehouse or an isolated fixture")
    state = rows(conn, "SELECT database_id, state_desc, user_access_desc, is_read_only, "
                 "is_read_committed_snapshot_on FROM sys.databases WHERE name=?", database)
    if len(state) != 1:
        raise RuntimeError("Source database is missing")
    files = rows(conn, "SELECT file_id, type_desc, physical_name, size * 8192 AS bytes "
                 "FROM sys.master_files WHERE database_id=DB_ID(?) ORDER BY file_id", database)
    return dict(state[0], files=files)


def status(conn, database=SOURCE):
    state = source_state(conn, database)
    recent = rows(conn, "SELECT TOP(1) backup_finish_date, is_copy_only, has_backup_checksums "
                  "FROM msdb.dbo.backupset WHERE database_name=? AND type='D' "
                  "ORDER BY backup_finish_date DESC", database)
    return {"source_online": state["state_desc"] == "ONLINE",
            "snapshot_reads_enabled": bool(state["is_read_committed_snapshot_on"]),
            "allocated_mb": round(sum(f["bytes"] for f in state["files"]) / 1024**2, 2),
            "recorded_full_backups": recent,
            "scope": "local same-instance database recovery only"}


def prepare_directory(path, sql_service=False):
    args = ["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
            str(DIRECTORY_HELPER), "-Directory", str(path)]
    if not path.exists():
        args.append("-Create")
    if sql_service:
        args.append("-SqlService")
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=20)
    proof = json.loads(result.stdout)
    if not proof.get("access_verified") or bool(proof.get("sql_service_access")) != sql_service:
        raise RuntimeError("Recovery directory access was not verified")
    return proof


def fingerprint(conn, database):
    name = identifier(database)
    queries = [
        f"SELECT s.name,o.name,o.type,m.definition FROM {name}.sys.objects o "
        f"JOIN {name}.sys.schemas s ON s.schema_id=o.schema_id "
        f"LEFT JOIN {name}.sys.sql_modules m ON m.object_id=o.object_id "
        "WHERE s.name IN ('sg','rpt') ORDER BY s.name,o.name,o.type",
        f"SELECT s.name,t.name,c.column_id,c.name,c.system_type_id,c.max_length,c.precision," 
        f"c.scale,c.is_nullable FROM {name}.sys.columns c "
        f"JOIN {name}.sys.objects t ON t.object_id=c.object_id "
        f"JOIN {name}.sys.schemas s ON s.schema_id=t.schema_id "
        "WHERE s.name IN ('sg','rpt') ORDER BY s.name,t.name,c.column_id",
        f"SELECT p.name,perm.class,perm.major_id,perm.minor_id,perm.permission_name,perm.state "
        f"FROM {name}.sys.database_permissions perm "
        f"JOIN {name}.sys.database_principals p ON p.principal_id=perm.grantee_principal_id "
        "WHERE p.name='rpt_reader' ORDER BY perm.class,perm.major_id,perm.minor_id,perm.permission_name",
    ]
    values = [rows(conn, query) for query in queries]
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()


def anchor(conn, database, doc_id=None):
    name = identifier(database)
    where = "doc_id=?" if doc_id else "observation_context=N'Controlled validation' AND signature_id=9000001"
    params = (doc_id,) if doc_id else ()
    result = rows(conn, f"SELECT doc_id FROM {name}.rpt.network_alerts WHERE {where}", *params)
    if len(result) != 1:
        raise RuntimeError("Expected one known controlled network record")
    doc_id = result[0]["doc_id"]
    digest = conn.execute(f"SELECT HASHBYTES('SHA2_256',CONVERT(varbinary(max),raw_json)) "
                          f"FROM {name}.sg.alerts WHERE doc_id=?", doc_id).fetchone()[0]
    return {"doc_id": doc_id, "payload_sha256": bytes(digest).hex()}


def restore_sql(target, backup, files, directory):
    name = restore_name(target)
    if not files or {f["Type"] for f in files} != {"D", "L"}:
        raise RuntimeError("Only ordinary SQL data/log files are supported")
    moves = []
    seen = set()
    for file in files:
        file_id = int(file["FileId"])
        if file_id <= 0 or file_id in seen:
            raise RuntimeError("Unexpected backup file identity")
        seen.add(file_id)
        suffix = ".ldf" if file["Type"] == "L" else ".mdf"
        destination = directory / f"{target}_{file_id}{suffix}"
        if destination.exists():
            raise RuntimeError("Restore destination already exists")
        moves.append(f"MOVE {literal(file['LogicalName'])} TO {literal(str(destination))}")
    return (f"RESTORE DATABASE {name} FROM DISK={literal(str(backup))} "
            "WITH FILE=1,CHECKSUM,RECOVERY," + ",".join(moves) + ",MAXTRANSFERSIZE=1048576")


def cleanup(conn, target, directory, database_id):
    name = restore_name(target)
    current = rows(conn, "SELECT database_id FROM sys.databases WHERE name=?", target)
    if len(current) != 1 or current[0]["database_id"] != database_id:
        raise RuntimeError("Disposable database identity changed; refusing cleanup")
    files = rows(conn, "SELECT physical_name FROM sys.master_files WHERE database_id=?", database_id)
    if not files or any(Path(f["physical_name"]).parent != directory for f in files):
        raise RuntimeError("Disposable files are outside this drill; refusing cleanup")
    clients = conn.execute("SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process=1 "
                           "AND session_id<>@@SPID AND database_id=?", database_id).fetchone()[0]
    if clients:
        raise RuntimeError("Another client is using the disposable copy; no disconnect performed")
    operation(conn, f"DROP DATABASE {name}")


def write_evidence(directory, filename, value):
    with (directory / filename).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, default=str)


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_drill(conn, database=SOURCE):
    if not conn.autocommit or conn.execute("SELECT DB_NAME()").fetchone()[0] != "master":
        raise RuntimeError("Recovery requires an autocommit master connection")
    before = source_state(conn, database)
    if (before["state_desc"] != "ONLINE" or before["user_access_desc"] != "MULTI_USER" or
            before["is_read_only"] or not before["is_read_committed_snapshot_on"]):
        raise RuntimeError("Source is not the expected online snapshot-reading warehouse")
    source_bytes = sum(f["bytes"] for f in before["files"])
    if source_bytes > 2 * 1024**3 or {f["type_desc"] for f in before["files"]} != {"ROWS", "LOG"}:
        raise RuntimeError("Source exceeds this bounded ordinary-file drill")
    if conn.execute("SELECT available_physical_memory_kb FROM sys.dm_os_sys_memory").fetchone()[0] < 2 * 1024**2:
        raise RuntimeError("Host has under 2 GB available memory; wait before recovery testing")
    if conn.execute(f"SELECT COUNT(*) FROM {identifier(database)}.sg.load_runs WHERE status='running' "
                    "AND finished_at_utc IS NULL AND started_at_utc>DATEADD(hour,-1,SYSUTCDATETIME())").fetchone()[0]:
        raise RuntimeError("A recent loader run is active; wait rather than interrupt it")
    if shutil.disk_usage(ROOT.parent).free < max(4 * 1024**3, source_bytes * 4):
        raise RuntimeError("Insufficient free space for backup and disposable restoration")

    prepare_directory(ROOT)
    directory = ROOT / ("sql-" + uuid.uuid4().hex)
    storage = prepare_directory(directory, sql_service=True)
    target = "WatchtideRestore_" + uuid.uuid4().hex
    if conn.execute("SELECT DB_ID(?)", target).fetchone()[0] is not None:
        raise RuntimeError("Disposable database already exists")
    backup = directory / "warehouse-copy-only.bak"
    initial = {"started_utc": datetime.now(timezone.utc).isoformat(), "source": before,
               "target": target, "storage": storage, "same_pc_only": True,
               "schema_sha256": fingerprint(conn, database), "anchor": anchor(conn, database)}
    write_evidence(directory, "preflight.json", initial)
    restored_id = None
    result = None
    try:
        operation(conn, f"BACKUP DATABASE {identifier(database)} TO DISK={literal(str(backup))} "
                  "WITH COPY_ONLY,CHECKSUM,COMPRESSION,STOP_ON_ERROR,MAXTRANSFERSIZE=1048576")
        header = rows(conn, f"RESTORE HEADERONLY FROM DISK={literal(str(backup))}")
        if (len(header) != 1 or header[0]["DatabaseName"] != database or
                header[0]["BackupType"] != 1 or not header[0]["IsCopyOnly"] or
                not header[0]["HasBackupChecksums"] or header[0]["IsDamaged"]):
            raise RuntimeError("Backup metadata does not match this copy-only drill")
        operation(conn, f"RESTORE VERIFYONLY FROM DISK={literal(str(backup))} WITH CHECKSUM,FILE=1")
        digest = file_hash(backup)
        write_evidence(directory, "backup-verified.json", {
            "backup_sha256": digest, "bytes": backup.stat().st_size,
            "backup_finished": header[0]["BackupFinishDate"], "backup_guid": header[0]["BackupSetGUID"]})
        files = rows(conn, f"RESTORE FILELISTONLY FROM DISK={literal(str(backup))} WITH FILE=1")
        if conn.execute("SELECT DB_ID(?)", target).fetchone()[0] is not None:
            raise RuntimeError("Disposable database appeared concurrently; no restore performed")
        operation(conn, restore_sql(target, backup, files, directory))
        restored_id = conn.execute("SELECT DB_ID(?)", target).fetchone()[0]
        operation(conn, f"ALTER DATABASE {restore_name(target)} SET READ_ONLY WITH NO_WAIT")
        operation(conn, f"DBCC CHECKDB ({restore_name(target)}) WITH NO_INFOMSGS,ALL_ERRORMSGS,MAXDOP=1",
                  reject_rows=True)
        if fingerprint(conn, target) != initial["schema_sha256"]:
            raise RuntimeError("Restored schema/report-role grants differ from the source baseline")
        if anchor(conn, target, initial["anchor"]["doc_id"]) != initial["anchor"]:
            raise RuntimeError("Controlled record payload differs after restoration")
        name = restore_name(target)
        views = rows(conn, f"SELECT v.name FROM {name}.sys.views v JOIN {name}.sys.schemas s "
                     "ON s.schema_id=v.schema_id WHERE s.name='rpt' ORDER BY v.name")
        if not views:
            raise RuntimeError("Restored reporting views are missing")
        view_counts = {}
        for view in views:
            view_counts[view["name"]] = conn.execute(
                f"SELECT COUNT_BIG(*) FROM {name}.rpt.{identifier(view['name'])}").fetchone()[0]
        result = {"restored_alerts": conn.execute(f"SELECT COUNT_BIG(*) FROM {name}.sg.alerts").fetchone()[0],
                  "report_views_checked": len(view_counts), "report_view_counts": view_counts,
                  "controlled_record_payload_matched": True, "schema_and_report_grants_matched": True,
                  "checkdb_passed": True, "backup_sha256": digest,
                  "backup_bytes": backup.stat().st_size, "same_pc_only": True,
                  "other_instance_login_recovery_tested": False, "wazuh_recovery_tested": False,
                  "backup_encryption_verified": False}
        if file_hash(backup) != digest:
            raise RuntimeError("Backup changed during the restore test")
    except Exception as exc:
        write_evidence(directory, "stopped.json", {"error_type": type(exc).__name__,
                                                   "target": target, "backup_retained": backup.exists()})
        raise
    finally:
        if restored_id is not None:
            cleanup(conn, target, directory, restored_id)

    after = source_state(conn, database)
    unchanged_fields = ("database_id", "state_desc", "user_access_desc", "is_read_only",
                        "is_read_committed_snapshot_on")
    same_files = [(f["file_id"], f["physical_name"]) for f in before["files"]] == [
        (f["file_id"], f["physical_name"]) for f in after["files"]]
    if not same_files or any(before[k] != after[k] for k in unchanged_fields):
        raise RuntimeError("Live warehouse identity/settings changed; review privately")
    prepare_directory(directory, sql_service=True)
    result.update({"completed_utc": datetime.now(timezone.utc).isoformat(),
                   "disposable_database_removed": True, "live_database_settings_unchanged": True})
    write_evidence(directory, "restore-passed.json", result)
    return directory, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="Create a private backup and disposable restore")
    args = parser.parse_args()
    pyodbc.pooling = False
    with pyodbc.connect(CONN_STR, autocommit=True, timeout=5) as conn:
        conn.timeout = 180 if args.run else 10
        if args.run:
            directory, result = run_drill(conn)
            summary = {k: v for k, v in result.items() if k != "report_view_counts"}
            print(json.dumps(summary, indent=2, default=str))
            print("PRIVATE_RECOVERY_EVIDENCE: " + str(directory))
            print("LOCAL_SQL_BACKUP_AND_RESTORE_PASSED")
        else:
            print(json.dumps(status(conn), indent=2, default=str))


if __name__ == "__main__":
    main()
