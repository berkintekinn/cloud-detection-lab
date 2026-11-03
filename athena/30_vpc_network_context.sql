-- Supporting context only. Replace UTC day and interface ID after mapping
-- the instance's ENI through EC2 inventory or DescribeNetworkInterfaces.
SELECT
  day,
  interface_id,
  srcaddr,
  dstaddr,
  dstport,
  action,
  log_status,
  sum(packets) AS packets,
  sum(bytes) AS bytes
FROM cloud_detection_lab.vpc_flow_logs
WHERE day BETWEEN '2026/11/03' AND '2026/11/03'
  AND interface_id = 'eni-REPLACE_ME'
  AND log_status = 'OK'
GROUP BY day, interface_id, srcaddr, dstaddr, dstport, action, log_status
ORDER BY bytes DESC
LIMIT 100;
