--all login attempts (success & fails)
SELECT 
    log_id,
    user_id,
    username,
    status,
    src_ip,
    attempt_time,
    details
FROM login_log
ORDER BY attempt_time DESC;
--only successfull logins
SELECT 
    username,
    src_ip,
    attempt_time,
    details
FROM login_log
WHERE status = 'SUCCESS'
ORDER BY attempt_time DESC;
-- only failed only
SELECT 
    username,
    src_ip,
    attempt_time,
    details
FROM login_log
WHERE status = 'FAILED'
ORDER BY attempt_time DESC;
-- loced account
SELECT 
    username,
    failed_attempts,
    locked_at
FROM secure_users
WHERE is_locked = 'Y';
--users with most failed attempts
SELECT 
    username,
    COUNT(*) AS failed_count
FROM login_log
WHERE status = 'FAILED'
GROUP BY username
ORDER BY failed_count DESC
FETCH FIRST 10 ROWS ONLY;
 -- daily summary of (success vs failed)
 SELECT 
    TRUNC(attempt_time) AS day,
    SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS success_count,
    SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS fail_count
FROM login_log
GROUP BY TRUNC(attempt_time)
ORDER BY day DESC;
--history of locked account
SELECT 
    a.username,
    l.lock_reason,
    l.lock_time,
    l.unlock_time,
    l.unlocked_by
FROM account_locks l
JOIN secure_users a ON a.user_id = l.user_id
ORDER BY l.lock_time DESC;
-- Single user login history
SELECT 
    log_id,
    status,
    attempt_time,
    src_ip,
    details
FROM login_log
WHERE username = 'test_user'
ORDER BY attempt_time DESC;

--Admin who unlocked users
SELECT 
    unlocked_by AS admin,
    user_id,
    lock_time,
    unlock_time
FROM account_locks
WHERE unlock_time IS NOT NULL
ORDER BY unlock_time DESC;

--All users with 3+ failed attempts (suspicious)
SELECT
    username,
    failed_attempts,
    is_locked,
    last_login
FROM secure_users
WHERE failed_attempts >= 3
ORDER BY failed_attempts DESC;

