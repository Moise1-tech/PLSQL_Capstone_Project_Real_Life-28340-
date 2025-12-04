

## Student: Ndaruhutse Moise
## ID: 28340
## DEPARTMENT: SOFTWARE Engineering
## Course:  Database Development with PL/SQL (INSY 8311)
## Instructor: Eric Maniraguha
## Date: 04/10/2025

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

