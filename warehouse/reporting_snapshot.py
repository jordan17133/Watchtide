r"""Opt-in reporting concurrency maintenance; not part of normal schema deployment.

Run with Power BI closed and the scheduled loader idle:
    .venv\Scripts\python.exe -m warehouse.reporting_snapshot --enable

Default is read-only status. Never kills sessions or rolls back another client.
"""

import argparse
import json
import re

import pyodbc

from warehouse.apply_sql import CONN_STR


DATABASE = "SentinelGridWarehouse"


def checked_database(database):
    if database != DATABASE and not re.fullmatch(r"WatchtideNetworkTest_[0-9a-f]{32}", database):
        raise ValueError("Only the warehouse or an isolated reporting test database is allowed")
    return f"[{database}]"


def status(conn, database=DATABASE):
    name = checked_database(database)
    cur = conn.cursor()
    row = cur.execute(
        "SELECT state_desc,user_access_desc,is_read_only,is_read_committed_snapshot_on "
        "FROM sys.databases WHERE name=?", database).fetchone()
    if row is None:
        raise RuntimeError("Target database does not exist")
    blockers = cur.execute(
        "SELECT DISTINCT s.session_id,s.program_name FROM sys.dm_exec_sessions s "
        "WHERE s.is_user_process=1 AND s.session_id<>@@SPID AND "
        "(s.database_id=DB_ID(?) OR EXISTS (SELECT 1 FROM sys.dm_tran_session_transactions st "
        "JOIN sys.dm_tran_database_transactions dt ON dt.transaction_id=st.transaction_id "
        "WHERE st.session_id=s.session_id AND dt.database_id=DB_ID(?)))",
        database, database).fetchall()
    memory_tables = cur.execute(
        f"SELECT COUNT(*) FROM {name}.sys.tables WHERE is_memory_optimized=1 AND durability=1"
    ).fetchone()[0]
    return {"state": row[0], "access": row[1], "read_only": bool(row[2]),
            "enabled": bool(row[3]), "schema_only_memory_tables": memory_tables,
            "other_connections": [{"session_id": r[0], "application": r[1]} for r in blockers]}


def set_snapshot(conn, enabled, database=DATABASE):
    name = checked_database(database)
    if not conn.autocommit:
        raise RuntimeError("Maintenance requires an autocommit master connection")
    if conn.execute("SELECT DB_NAME()").fetchone()[0] != "master":
        raise RuntimeError("Maintenance must connect to master")
    before = status(conn, database)
    if before["state"] != "ONLINE" or before["access"] != "MULTI_USER" or before["read_only"]:
        raise RuntimeError("Target must be online, writable and multi-user")
    if before["enabled"] == enabled:
        return {"changed": False, "enabled": enabled}
    if before["schema_only_memory_tables"]:
        raise RuntimeError("Refusing a change that could discard schema-only memory-table data")
    if before["other_connections"]:
        raise RuntimeError("Database is not quiet; close reporting clients and wait for the loader")
    # NO_WAIT also protects the race between preflight and ALTER DATABASE.
    conn.execute("SET LOCK_TIMEOUT 5000")
    conn.execute(f"ALTER DATABASE {name} SET READ_COMMITTED_SNAPSHOT {'ON' if enabled else 'OFF'} WITH NO_WAIT")
    after = status(conn, database)
    if after["enabled"] != enabled:
        raise RuntimeError("Database option did not match the requested state")
    return {"changed": True, "enabled": enabled}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--enable", action="store_true")
    mode.add_argument("--disable", action="store_true", help="Quiet-window rollback to locking reads")
    args = parser.parse_args()
    pyodbc.pooling = False
    conn = pyodbc.connect(CONN_STR, autocommit=True, timeout=5)
    conn.timeout = 15
    try:
        result = set_snapshot(conn, args.enable) if args.enable or args.disable else status(conn)
        print(json.dumps(result, indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
