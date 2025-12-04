

## Student: Ndaruhutse Moise
## ID: 28340
## DEPARTMENT: SOFTWARE Engineering
## Course:  Database Development with PL/SQL (INSY 8311)
## Instructor: Eric Maniraguha
## Date: 01/12/2025

 ## Project Title: SECURE USER LOGIN AND ACTIVITY LOGGING SYSTEM

  ## PHASE I: Problem Statement & Presentation

  Problem Definition:
In most information systems, data security and controlled access are essential to prevent
unauthorized use and protect sensitive information. Many organizations face challenges in
managing user authentication, preventing unauthorized access, and tracking user activity within
their databases.
This project aims to design a secure user login and activity logging system using PL/SQL that
ensures only authorized users can access the system and all login activities are properly
recorded for security auditing. The system will maintain a record of all users, their credentials
(stored in a secure, encrypted form), and their roles (such as admin or normal user).
When a user attempts to log in, the system will verify their credentials, authenticate them
securely, and record whether the attempt was successful or failed. All login attempts will be
logged into a separate table for auditing purposes. Administrators will have the ability to view
the login history of all users to monitor suspicious activities and ensure accountability.
The project demonstrates essential database security concepts such as:
• Data encryption and password hashing

• Role-based access control
• User authentication
• Activity auditing and logging
• Error handling and access restriction
This system can be further extended to include advanced security features such as account
lockout after multiple failed attempts, password expiration policies, and user activity tracking
across multiple sessions.

##  PHASE II: Business Process Modeling

Scope (what’s modeled): the end-to-end login and auditing process for an application that uses the database authentication service. It covers: user login attempts, credential validation, success/failure handling, failed-attempt lockout, admin unlock, and audit/log recording. The model stops at application-level business flows (it does not include third-party identity providers or MFA flows — those may be added later).

MIS relevance: This process is core to information security and access control — a Management Information System (MIS) needs accurate, auditable authentication events to support compliance, incident investigation, access reporting, and KPI dashboards (e.g., failed attempts trend, lockouts by user/department). The model shows where operational data flows into the MIS (login_log, audit_log, account_lock history) enabling analytics and decision support.

Objectives & outcomes:

Ensure only authorized users gain access (authentication).

Record every login attempt for forensic and reporting needs.

Automatically lock accounts after configurable failed attempts to reduce brute-force risk.

Allow administrators to review and unlock accounts with audit trail.

Provide structured data for MIS dashboards (failed/successful attempts, peak login times, suspicious accounts).

Main components & roles:

User (actor): submits credentials via client (web/mobile).

Application (actor): forwards credentials to DB auth package and displays result.

Auth Service (DB package): validates credentials, updates secure_users, writes login_log, account_locks, and audit_log.

Admin (actor): views login history, unlocks accounts using DB procedures.

Auditor / MIS analyst (actor): queries logs and KPIs for reports.

Organizational impact & analytics opportunities: The process centralizes auth data enabling MIS to produce KPIs (success rate, lockout frequency, suspicious user lists). This drives decisions on password policy, training, and detection rules. Auditing supports compliance (who changed user status, when).

Secure login BPMN diagram

<img width="1536" height="1024" alt="Image" src="https://github.com/user-attachments/assets/d0243522-ff45-4f7b-981e-50c2fb2988de" />
flowchart TD
  A[Start] --> B[User enters credentials]
  B --> C[App calls pkg_auth.authenticate(username,password,src_ip)]
  C --> D{Username exists?}
  D -- No --> E[Insert LOGIN_LOG(status=FAILED, details='Unknown username')]
  E --> Z[End]
  D -- Yes --> F{Account locked?}
  F -- Yes --> G[Insert LOGIN_LOG(status=FAILED, details='Account locked')]
  G --> Z
  F -- No --> H{Password correct?}
  H -- Yes --> I[Update secure_users failed_attempts=0, last_login]
  I --> J[Insert LOGIN_LOG(status=SUCCESS)]
  J --> K[Return SUCCESS to App]
  K --> Z
  H -- No --> L[Increment failed_attempts]
  L --> M{failed_attempts >= threshold?}
  M -- No --> N[Insert LOGIN_LOG(status=FAILED)]
  N --> Z
  M -- Yes --> O[Update secure_users is_locked='Y', locked_at; Insert ACCOUNT_LOCKS; Insert LOGIN_LOG(status=FAILED-lockout)]
  O --> P[Optional: Notify Admin]
  P --> Z  generate diagram
<img width="1024" height="1536" alt="Image" src="https://github.com/user-attachments/assets/a9277dc6-9854-416e-8ee3-e22308bbe899" />
Phase III Logical model (ERD & Data Dictionary)

Below is the ERD represented in text and the main data dictionary. This matches your uploaded ERD idea and extends it for lockout/audit/holidays.
Data Dictionary (condensed — expand in README)
Table	Column	Type	Constraints	Purpose
SECURE_USERS	user_id	NUMBER GENERATED BY DEFAULT AS IDENTITY	PK	user identifier
	username	VARCHAR2(50)	UNIQUE, NOT NULL	login name
	password_hash	VARCHAR2(200)	NOT NULL	SHA-256 hash
	role	VARCHAR2(20)	DEFAULT 'USER'	USER / ADMIN
	is_locked	CHAR(1)	'Y'/'N' default 'N'	locked flag
	failed_attempts	NUMBER	DEFAULT 0	count of consecutive fails
	locked_at	TIMESTAMP	nullable	lock timestamp
	created_at	TIMESTAMP	default systimestamp	account creation
	last_login	TIMESTAMP	nullable	last successful login
LOGIN_LOG	log_id	NUMBER GENERATED ...	PK	login attempt record
	user_id	NUMBER	FK -> SECURE_USERS.user_id	associated user
	username	VARCHAR2(50)	redundant for historical queries	
	status	VARCHAR2(10)	'SUCCESS'/'FAILED'	outcome
	src_ip	VARCHAR2(45)		source IP
	attempt_time	TIMESTAMP	default systimestamp	timestamp
ACCOUNT_LOCKS	lock_id	NUMBER	PK	lock history
...	...	...	...	...
AUDIT_LOG	audit_id	NUMBER	PK	dml/audit records
HOLIDAYS	holiday_date	DATE	PK	holiday calendar

<img width="1024" height="1024" alt="Image" src="https://github.com/user-attachments/assets/2ed50d35-0b10-44f2-b7d5-ca65079edbaa" />
<img width="1024" height="1024" alt="Image" src="https://github.com/user-attachments/assets/1ef15624-83ce-4de4-893b-1271df7ee6e5" />

 PHASE IV: Database Creation
 Objective: Create and configure Oracle pluggable database.
 Requirements
 Database Setup:
 Naming Format: 
mon_28340_Moise_securesystem_DB 
-- Run as SYS or DBA
CREATE USER moise_admin IDENTIFIED BY Moise DEFAULT TABLESPACE users TEMPORARY TABLESPACE temp;
GRANT CONNECT, RESOURCE, CREATE VIEW, CREATE PROCEDURE, CREATE TRIGGER, CREATE SEQUENCE, CREATE TYPE TO moise_admin;

![Image](https://github.com/user-attachments/assets/b2036c55-014a-41d5-8fea-79cdedbd0755)

 PHASE V: Table Implementation & Data Insertion
 A) CREATE TABLE scripts
 -- Run as moise_admin
CREATE TABLE secure_users (
  user_id      NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY,
  username     VARCHAR2(50) UNIQUE NOT NULL,
  password_hash VARCHAR2(200) NOT NULL,
  role         VARCHAR2(20) DEFAULT 'USER' NOT NULL,
  is_locked    CHAR(1) DEFAULT 'N' CHECK (is_locked IN ('Y','N')),
  failed_attempts NUMBER DEFAULT 0,
  locked_at    TIMESTAMP NULL,
  created_at   TIMESTAMP DEFAULT SYSTIMESTAMP,
  last_login   TIMESTAMP NULL
);

CREATE TABLE login_log (
  log_id       NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY,
  user_id      NUMBER NULL,
  username     VARCHAR2(50) NOT NULL,
  status       VARCHAR2(10) CHECK (status IN ('SUCCESS','FAILED')),
  src_ip       VARCHAR2(45),
  attempt_time TIMESTAMP DEFAULT SYSTIMESTAMP,
  details      VARCHAR2(4000),
  CONSTRAINT fk_login_user FOREIGN KEY (user_id) REFERENCES secure_users(user_id)
);

CREATE TABLE account_locks (
  lock_id      NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY,
  user_id      NUMBER NOT NULL,
  lock_reason  VARCHAR2(200),
  lock_time    TIMESTAMP DEFAULT SYSTIMESTAMP,
  unlock_time  TIMESTAMP NULL,
  unlocked_by  VARCHAR2(50),
  CONSTRAINT fk_lock_user FOREIGN KEY (user_id) REFERENCES secure_users(user_id)
);

CREATE TABLE holidays (
  holiday_date DATE PRIMARY KEY,
  description  VARCHAR2(200)
);

CREATE TABLE audit_log (
  audit_id     NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY,
  table_name   VARCHAR2(100),
  action       VARCHAR2(20),
  performed_by VARCHAR2(50),
  performed_at TIMESTAMP DEFAULT SYSTIMESTAMP,
  success_flag CHAR(1) CHECK (success_flag IN ('Y','N')),
  details      VARCHAR2(4000)
);

B) Bulk data population (200 users + 1000 random login attempts)

I used PL/SQL to generate realistic test data including some failed attempts and lockouts.
BEGIN
  -- create admin user
  INSERT INTO secure_users (username, password_hash, role)
  VALUES ('admin', STANDARD_HASH('Admin@123','SHA256'), 'ADMIN');

  -- create 199 regular users
  FOR i IN 1..199 LOOP
    INSERT INTO secure_users (username, password_hash)
    VALUES (
      'user_' || lpad(i,3,'0'),
      STANDARD_HASH('P@ss' || i, 'SHA256')
    );
  END LOOP;
  COMMIT;
END;
/

-- Create randomized login attempts: mixture of successes and failures
DECLARE
  v_count NUMBER := 1000;
  v_user_count NUMBER;
  v_user_id NUMBER;
  v_username VARCHAR2(50);
  v_status VARCHAR2(10);
  v_ip VARCHAR2(45);
BEGIN
  SELECT COUNT(*) INTO v_user_count FROM secure_users;

  FOR i IN 1..v_count LOOP
    -- pick a random user
    v_user_id := TRUNC(DBMS_RANDOM.VALUE(1, v_user_count+1));
    SELECT username INTO v_username FROM secure_users WHERE user_id = v_user_id;

    -- randomly decide status, make ~15% failures
    IF DBMS_RANDOM.VALUE(0,1) < 0.15 THEN
      v_status := 'FAILED';
    ELSE
      v_status := 'SUCCESS';
    END IF;

    v_ip := TO_CHAR(TRUNC(DBMS_RANDOM.VALUE(1,255))) || '.' ||
            TO_CHAR(TRUNC(DBMS_RANDOM.VALUE(1,255))) || '.' ||
            TO_CHAR(TRUNC(DBMS_RANDOM.VALUE(1,255))) || '.' ||
            TO_CHAR(TRUNC(DBMS_RANDOM.VALUE(1,255)));

    INSERT INTO login_log (user_id, username, status, src_ip, details)
    VALUES (v_user_id, v_username, v_status, v_ip, 'Auto-generated test data');
  END LOOP;
  COMMIT;
END;
/

Phase VI — PL/SQL: package, functions, procedures, cursors, tests
Below is a consolidated security package exposing the API the application calls.

Security package spec & body

CREATE OR REPLACE PACKAGE pkg_auth IS
  -- config
  c_lock_threshold CONSTANT NUMBER := 5; -- failed attempts
  c_lock_duration_minutes CONSTANT NUMBER := 30;

  FUNCTION hash_password(p_plain IN VARCHAR2) RETURN VARCHAR2;
  PROCEDURE create_user(p_username IN VARCHAR2, p_password IN VARCHAR2, p_role IN VARCHAR2 := 'USER');
  PROCEDURE authenticate(p_username IN VARCHAR2, p_password IN VARCHAR2, p_src_ip IN VARCHAR2, p_result OUT VARCHAR2);
  PROCEDURE unlock_user(p_username IN VARCHAR2, p_admin IN VARCHAR2);
  FUNCTION is_holiday(p_date IN DATE) RETURN BOOLEAN;
END pkg_auth;
/
CREATE OR REPLACE PACKAGE BODY pkg_auth IS

  FUNCTION hash_password(p_plain IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN STANDARD_HASH(p_plain, 'SHA256');
  END;

  PROCEDURE create_user(p_username IN VARCHAR2, p_password IN VARCHAR2, p_role IN VARCHAR2 := 'USER') IS
  BEGIN
    INSERT INTO secure_users(username, password_hash, role)
    VALUES (p_username, hash_password(p_password), p_role);
    INSERT INTO audit_log(table_name, action, performed_by, success_flag, details)
    VALUES ('SECURE_USERS', 'INSERT', USER, 'Y', 'Created user '||p_username);
    COMMIT;
  EXCEPTION
    WHEN OTHERS THEN
      INSERT INTO audit_log(table_name, action, performed_by, success_flag, details)
      VALUES ('SECURE_USERS', 'INSERT', USER, 'N', SQLERRM||' for '||p_username);
      RAISE;
  END;

  PROCEDURE authenticate(p_username IN VARCHAR2, p_password IN VARCHAR2, p_src_ip IN VARCHAR2, p_result OUT VARCHAR2) IS
    v_hashed VARCHAR2(200);
    v_user_id NUMBER;
    v_is_locked CHAR(1);
    v_failed NUMBER;
  BEGIN
    SELECT user_id, password_hash, is_locked, failed_attempts
      INTO v_user_id, v_hashed, v_is_locked, v_failed
      FROM secure_users
     WHERE username = p_username;

    IF v_is_locked = 'Y' THEN
      p_result := 'LOCKED';
      INSERT INTO login_log(user_id, username, status, src_ip, details)
      VALUES (v_user_id, p_username, 'FAILED', p_src_ip, 'Account locked');
      COMMIT;
      RETURN;
    END IF;

    IF v_hashed = hash_password(p_password) THEN
      -- success
      UPDATE secure_users SET failed_attempts = 0, last_login = SYSTIMESTAMP WHERE user_id = v_user_id;
      INSERT INTO login_log(user_id, username, status, src_ip, details)
        VALUES (v_user_id, p_username, 'SUCCESS', p_src_ip, 'Authenticated');
      p_result := 'SUCCESS';
      COMMIT;
    ELSE
      -- failed attempt
      v_failed := v_failed + 1;
      UPDATE secure_users SET failed_attempts = v_failed WHERE user_id = v_user_id;
      INSERT INTO login_log(user_id, username, status, src_ip, details)
        VALUES (v_user_id, p_username, 'FAILED', p_src_ip, 'Bad password');
      -- if threshold reached, lock account
      IF v_failed >= c_lock_threshold THEN
        UPDATE secure_users SET is_locked = 'Y', locked_at = SYSTIMESTAMP WHERE user_id = v_user_id;
        INSERT INTO account_locks(user_id, lock_reason) VALUES (v_user_id, 'Lockout after '||v_failed||' failed attempts');
      END IF;
      p_result := 'FAILED';
      COMMIT;
    END IF;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      -- record failed unknown username
      INSERT INTO login_log(user_id, username, status, src_ip, details)
        VALUES (NULL, p_username, 'FAILED', p_src_ip, 'Unknown username');
      p_result := 'UNKNOWN';
      COMMIT;
  END;

  PROCEDURE unlock_user(p_username IN VARCHAR2, p_admin IN VARCHAR2) IS
    v_user_id NUMBER;
  BEGIN
    SELECT user_id INTO v_user_id FROM secure_users WHERE username = p_username;
    UPDATE secure_users SET is_locked = 'N', failed_attempts = 0, locked_at = NULL WHERE user_id = v_user_id;
    UPDATE account_locks SET unlock_time = SYSTIMESTAMP, unlocked_by = p_admin
      WHERE user_id = v_user_id AND unlock_time IS NULL;
    INSERT INTO audit_log(table_name, action, performed_by, success_flag, details)
      VALUES ('SECURE_USERS', 'UNLOCK', p_admin, 'Y', 'Unlocked '||p_username);
    COMMIT;
  EXCEPTION WHEN NO_DATA_FOUND THEN
    INSERT INTO audit_log(table_name, action, performed_by, success_flag, details)
      VALUES ('SECURE_USERS', 'UNLOCK', p_admin, 'N', 'User not found '||p_username);
    COMMIT;
  END;

  FUNCTION is_holiday(p_date IN DATE) RETURN BOOLEAN IS
    v_cnt NUMBER;
  BEGIN
    SELECT COUNT(*) INTO v_cnt FROM holidays WHERE TRUNC(holiday_date) = TRUNC(p_date);
    RETURN v_cnt > 0;
  END;

END pkg_auth;
/
Cursors
 cursor to fetch suspicious users (many failed attempts):

DECLARE
  CURSOR c_suspicious IS
    SELECT username, failed_attempts, is_locked, last_login
      FROM secure_users
     WHERE failed_attempts >= 3
     ORDER BY failed_attempts DESC;
BEGIN
  FOR r IN c_suspicious LOOP
    DBMS_OUTPUT.PUT_LINE(r.username || ' fails=' || r.failed_attempts || ' locked=' || r.is_locked);
  END LOOP;
END;
/

Phase VII — Advanced programming, triggers & auditing
1) Trigger: audit DML on SECURE_USERS

CREATE OR REPLACE TRIGGER trg_audit_secure_users
AFTER INSERT OR UPDATE OR DELETE ON secure_users
FOR EACH ROW
DECLARE
  v_action VARCHAR2(20);
BEGIN
  IF INSERTING THEN v_action := 'INSERT';
  ELSIF UPDATING THEN v_action := 'UPDATE';
  ELSIF DELETING THEN v_action := 'DELETE';
  END IF;

  INSERT INTO audit_log(table_name, action, performed_by, success_flag, details)
  VALUES ('SECURE_USERS', v_action, USER, 'Y', 'Row user=' || NVL(:NEW.username, :OLD.username));

EXCEPTION
  WHEN OTHERS THEN
    NULL; -- avoid breaking DML path; log failures elsewhere if needed
END;
/

2) Business rule: Restrict DML by date (Phase VII requirement)

My course requires a rule like “Employees CANNOT INSERT/UPDATE/DELETE on WEEKDAYS (Mon-Fri) and PUBLIC HOLIDAYS.” Implementing exactly: Block non-admins from changing SECURE_USERS on weekdays and holidays. (Admins allowed; this is an exercise — in production you'd use a different rule.)
CREATE OR REPLACE TRIGGER trg_restrict_user_changes
BEFORE INSERT OR UPDATE OR DELETE ON secure_users
FOR EACH ROW
DECLARE
  v_weekday NUMBER;
  v_is_hol  BOOLEAN;
BEGIN
  -- allow DBA or admins (simple check; in real life check SESSION_USER properly)
  IF USER = 'MOISE_ADMIN' THEN
    RETURN;
  END IF;

  -- find current weekday (1=Sunday, 2=Monday ... 7=Saturday)
  SELECT TO_CHAR(SYSDATE, 'D') INTO v_weekday FROM DUAL;

  v_is_hol := pkg_auth.is_holiday(TRUNC(SYSDATE));

  -- if weekday (Mon-Fri -> depending on NLS_TERRITORY, safer to use day name):
  IF NOT (TO_CHAR(SYSDATE,'DY','NLS_DATE_LANGUAGE=ENGLISH') IN ('SAT','SUN')) OR v_is_hol THEN
    RAISE_APPLICATION_ERROR(-20001, 'DML on SECURE_USERS is restricted on weekdays and public holidays.');
  END IF;

EXCEPTION
  WHEN OTHERS THEN
    RAISE;
END;
/

Note: The check uses the environment NLS settings; in my deployment you may need to adapt NLS_TERRITORY or use NEXT_DAY logic. This trigger demonstrates how to apply the exact course requirement (deny modifications on weekdays and holidays). Adjust as needed.

Phase VIII — Documentation, BI & Presentation
BI: KPI definitions & sample analytics queries

KPIs

Daily Login Volume (count of attempts/day)

Success Rate (%) = success / total

Failed Attempts Trend (7-day moving average)

Locked Accounts Count (current)

Top 10 users by failed attempts (suspicious)

Login origin distribution (by src_ip / country — requires GeoIP enrichment)

Sample queries

-- Daily success/failure
SELECT TRUNC(attempt_time) day,
       SUM(CASE WHEN status='SUCCESS' THEN 1 ELSE 0 END) success_count,
       SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) fail_count
FROM login_log
GROUP BY TRUNC(attempt_time)
ORDER BY day DESC;

-- Top suspicious users
SELECT username, COUNT(*) failed_count
FROM login_log
WHERE status = 'FAILED'
GROUP BY username
ORDER BY failed_count DESC
FETCH FIRST 10 ROWS ONLY;

-- Current locked accounts
SELECT username, failed_attempts, locked_at FROM secure_users WHERE is_locked='Y';

