-- Default 14-field text format and non-Hive daily S3 path only.
-- Replace placeholders and start date. Create another table per account/Region.
CREATE EXTERNAL TABLE IF NOT EXISTS cloud_detection_lab.vpc_flow_logs (
  version int,
  account_id string,
  interface_id string,
  srcaddr string,
  dstaddr string,
  srcport int,
  dstport int,
  protocol bigint,
  packets bigint,
  bytes bigint,
  start bigint,
  `end` bigint,
  action string,
  log_status string
)
PARTITIONED BY (day string)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY ' '
LOCATION 's3://<LOG_BUCKET>/AWSLogs/<ACCOUNT_ID>/vpcflowlogs/<REGION>/'
TBLPROPERTIES (
  'skip.header.line.count'='1',
  'projection.enabled'='true',
  'projection.day.type'='date',
  'projection.day.format'='yyyy/MM/dd',
  'projection.day.range'='2026/01/01,NOW',
  'projection.day.interval'='1',
  'projection.day.interval.unit'='DAYS',
  'storage.location.template'='s3://<LOG_BUCKET>/AWSLogs/<ACCOUNT_ID>/vpcflowlogs/<REGION>/${day}/'
);
