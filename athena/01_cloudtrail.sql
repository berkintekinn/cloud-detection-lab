-- Replace <LOG_BUCKET>, <ACCOUNT_ID>, <REGION>, and the date range.
-- One table per account and delivered Region; include IAM global events.
CREATE DATABASE IF NOT EXISTS cloud_detection_lab;

CREATE EXTERNAL TABLE IF NOT EXISTS cloud_detection_lab.cloudtrail_management (
  eventversion string,
  useridentity struct<
    type:string,
    principalid:string,
    arn:string,
    accountid:string,
    accesskeyid:string,
    username:string,
    sessioncontext:struct<
      sessionissuer:struct<arn:string,username:string>
    >
  >,
  eventtime string,
  eventsource string,
  eventname string,
  awsregion string,
  sourceipaddress string,
  useragent string,
  errorcode string,
  errormessage string,
  requestparameters string,
  responseelements string,
  requestid string,
  eventid string,
  readonly string,
  eventtype string,
  recipientaccountid string,
  eventcategory string
)
PARTITIONED BY (day string)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<LOG_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/'
TBLPROPERTIES (
  'projection.enabled'='true',
  'projection.day.type'='date',
  'projection.day.format'='yyyy/MM/dd',
  'projection.day.range'='2026/01/01,NOW',
  'projection.day.interval'='1',
  'projection.day.interval.unit'='DAYS',
  'storage.location.template'='s3://<LOG_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/${day}/'
);
