

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
