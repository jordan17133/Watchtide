-- Watchtide: project saved Suricata alert fields without changing stored telemetry.
-- Labels distinguish validation/replay from unclassified alerts, never prove an incident.
USE SentinelGridWarehouse;
GO

CREATE OR ALTER VIEW rpt.network_alerts AS
WITH network AS (
    SELECT a.doc_id, a.index_name, a.wazuh_alert_id, a.alert_ts_utc,
           a.loaded_at_utc, a.agent_id, a.rule_id, a.rule_level,
           a.rule_description, j.payload,
           JSON_VALUE(j.payload, '$.data.timestamp') AS eve_timestamp_text,
           JSON_VALUE(j.payload, '$.data."@watchtide_validation"') AS validation_label,
           JSON_VALUE(j.payload, '$.data.pkt_src') AS packet_source
    FROM sg.alerts AS a
    CROSS APPLY (VALUES (CASE WHEN ISJSON(a.raw_json) = 1 THEN a.raw_json ELSE N'{}' END)) AS j(payload)
    WHERE JSON_VALUE(j.payload, '$.data.event_type') = N'alert'
      AND LEFT(LTRIM(JSON_QUERY(j.payload, '$.rule.groups')), 1) = N'['
      AND EXISTS (SELECT 1 FROM OPENJSON(j.payload, '$.rule.groups') AS g
                  WHERE g.[type] = 1 AND g.[value] COLLATE Latin1_General_100_BIN2 = N'suricata')
), parsed AS (
    SELECT n.*,
           TRY_CONVERT(datetimeoffset(6),
               CASE WHEN RIGHT(n.eve_timestamp_text, 5) LIKE '[-+][0-9][0-9][0-9][0-9]'
                    THEN STUFF(n.eve_timestamp_text, LEN(n.eve_timestamp_text) - 1, 0, ':')
                    ELSE NULLIF(n.eve_timestamp_text, N'') END) AS eve_time,
           TRY_CONVERT(int, JSON_VALUE(n.payload, '$.data.src_port')) AS source_port,
           TRY_CONVERT(int, JSON_VALUE(n.payload, '$.data.dest_port')) AS destination_port
    FROM network AS n
)
SELECT
    n.doc_id,
    n.index_name,
    n.wazuh_alert_id,
    n.alert_ts_utc,
    CAST(n.alert_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(3)) AS alert_time_local,
    DATEADD(hour, DATEDIFF(hour, 0,
        CAST(n.alert_ts_utc AT TIME ZONE 'UTC' AT TIME ZONE 'Eastern Standard Time' AS datetime2(3))), 0) AS alert_hour_local,
    n.loaded_at_utc,
    n.agent_id,
    ag.agent_name,
    n.rule_id,
    n.rule_level,
    n.rule_description,
    CAST(SWITCHOFFSET(n.eve_time, '+00:00') AS datetime2(6)) AS eve_timestamp_utc,
    CAST(n.eve_timestamp_text AS nvarchar(64)) AS eve_timestamp_text,
    CAST(JSON_VALUE(n.payload, '$.data.src_ip') AS nvarchar(64)) AS source_ip,
    CAST(JSON_VALUE(n.payload, '$.data.dest_ip') AS nvarchar(64)) AS destination_ip,
    CASE WHEN n.source_port BETWEEN 0 AND 65535 THEN n.source_port END AS source_port,
    CASE WHEN n.destination_port BETWEEN 0 AND 65535 THEN n.destination_port END AS destination_port,
    CAST(JSON_VALUE(n.payload, '$.data.proto') AS nvarchar(32)) AS protocol,
    CAST(JSON_VALUE(n.payload, '$.data.app_proto') AS nvarchar(64)) AS app_protocol,
    TRY_CONVERT(bigint, JSON_VALUE(n.payload, '$.data.alert.signature_id')) AS signature_id,
    CAST(JSON_VALUE(n.payload, '$.data.alert.signature') AS nvarchar(512)) AS signature,
    TRY_CONVERT(int, JSON_VALUE(n.payload, '$.data.alert.rev')) AS signature_revision,
    TRY_CONVERT(int, JSON_VALUE(n.payload, '$.data.alert.severity')) AS suricata_priority,
    CAST(JSON_VALUE(n.payload, '$.data.alert.category') AS nvarchar(256)) AS category,
    CAST(JSON_VALUE(n.payload, '$.data.alert.action') AS nvarchar(32)) AS alert_action,
    -- Suricata flow IDs may exceed signed-bigint or floating-point precision.
    CAST(JSON_VALUE(n.payload, '$.data.flow_id') AS nvarchar(64)) AS flow_id,
    CAST(n.packet_source AS nvarchar(64)) AS packet_source,
    TRY_CONVERT(tinyint, JSON_VALUE(n.payload, '$.data.icmp_type')) AS icmp_type,
    TRY_CONVERT(tinyint, JSON_VALUE(n.payload, '$.data.icmp_code')) AS icmp_code,
    CAST(n.validation_label AS nvarchar(128)) AS validation_label,
    CAST(CASE WHEN n.validation_label COLLATE Latin1_General_100_BIN2 = N'controlled-offline-suricata-pilot'
              THEN N'Controlled validation'
              WHEN n.validation_label COLLATE Latin1_General_100_BIN2 = N'controlled-live-suricata-trial'
              THEN N'Controlled live validation'
              WHEN n.validation_label IS NOT NULL AND n.validation_label <> N'' THEN N'Labeled validation'
              WHEN n.packet_source = N'wire/pcap' THEN N'Offline replay'
              ELSE N'Unclassified' END AS nvarchar(32)) AS observation_context
FROM parsed AS n
LEFT JOIN sg.agents AS ag ON ag.agent_id = n.agent_id;
GO
