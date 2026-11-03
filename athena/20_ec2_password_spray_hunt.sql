-- Five-minute fixed UTC bins approximate the Sigma rolling window.
-- Adjacent-bin events can be split: inspect raw events +/- 5 minutes around hits.
WITH denied AS (
  SELECT
    eventtime,
    eventid,
    useridentity.arn AS actor_arn,
    sourceipaddress,
    json_extract_scalar(requestparameters, '$.instanceId') AS instance_id,
    from_unixtime(
      300 * floor(to_unixtime(from_iso8601_timestamp(eventtime)) / 300)
    ) AS window_start
  FROM cloud_detection_lab.cloudtrail_management
  WHERE day BETWEEN '2026/11/03' AND '2026/11/03'
    AND eventsource = 'ec2.amazonaws.com'
    AND eventname = 'GetPasswordData'
    AND errorcode = 'Client.UnauthorizedOperation'
    AND useridentity.arn IS NOT NULL
)
SELECT
  window_start,
  actor_arn,
  count(DISTINCT eventid) AS denied_calls,
  count(DISTINCT instance_id) AS distinct_instance_ids,
  array_agg(DISTINCT sourceipaddress) AS source_ips
FROM denied
GROUP BY window_start, actor_arn
HAVING count(DISTINCT eventid) >= 5
ORDER BY window_start DESC
LIMIT 100;
