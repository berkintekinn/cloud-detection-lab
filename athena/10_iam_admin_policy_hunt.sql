-- Set the UTC day range to the test window. Query IAM-delivered Region.
-- Alert condition: successful attachment of AWS-managed AdministratorAccess.
SELECT
  eventtime,
  eventid,
  useridentity.arn AS actor_arn,
  sourceipaddress,
  useragent,
  json_extract_scalar(requestparameters, '$.userName') AS target_user,
  json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
  errorcode
FROM cloud_detection_lab.cloudtrail_management
WHERE day BETWEEN '2026/11/03' AND '2026/11/03'
  AND eventsource = 'iam.amazonaws.com'
  AND eventname = 'AttachUserPolicy'
  AND json_extract_scalar(requestparameters, '$.policyArn')
      = 'arn:aws:iam::aws:policy/AdministratorAccess'
  AND errorcode IS NULL
ORDER BY eventtime DESC
LIMIT 100;

-- Follow-up pivot: query CreateUser and CreateAccessKey for the same target_user
-- and actor_arn in a narrow UTC window. The single attachment alone does not
-- prove that a new user or key was created.
