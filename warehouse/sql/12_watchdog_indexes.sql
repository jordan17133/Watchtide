-- Watchtide warehouse: indexes for the collection watchdog and health check.
-- Measured 2026-10-08 on the live warehouse (44,107 alerts, about 351 MB with raw JSON in-row):
-- the watchdog's security tier read 21,379 pages and the health check's source query 19,108
-- pages per run, because neither filter had a usable index. Under host memory pressure those
-- full reads produced 10-15 second checks and timeouts.
-- Safe to re-run: every index is created only if it is missing. Built ONLINE, so loads continue.

USE SentinelGridWarehouse;
GO

-- New alerts by load time: the security tier reads only what loaded since its last checkpoint.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_alerts_loaded' AND object_id = OBJECT_ID(N'sg.alerts'))
    CREATE INDEX IX_alerts_loaded ON sg.alerts (loaded_at_utc) INCLUDE (rule_id, rule_level) WITH (ONLINE = ON);
GO

-- One agent's recent alerts: freshness, queue, Sysmon-error and per-source health queries.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_alerts_agent_ts' AND object_id = OBJECT_ID(N'sg.alerts'))
    CREATE INDEX IX_alerts_agent_ts ON sg.alerts (agent_id, alert_ts_utc) INCLUDE (rule_id, win_event_id, event_channel) WITH (ONLINE = ON);
GO
