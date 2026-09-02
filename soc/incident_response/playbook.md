# Incident Response Playbook

SentinelPulse SOC Analytics — NIST SP 800-61 aligned response procedures.

Based on the NIST SP 800-61 incident response lifecycle, this playbook covers the alerts the detection pipeline generates. When a rule fires, the corresponding procedure below is what the on-call analyst executes.

---

## The four phases

```
Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident
```

**Preparation** — monitoring is running, the team knows their roles, this playbook is current.

**Detection and Analysis** — an alert fires. First job is to confirm whether it is real or a false positive.

**Containment, Eradication, Recovery** — stop the spread, remove the threat, restore normal operations.

**Post-Incident** — write the report, tune the rules so the next catch comes earlier.

---

## Playbook: SSH Brute Force (RULE-001 / RULE-007 / RULE-BF — T1110)

1. Identify the source IP from the alert
2. Count total failed attempts and the time window density
3. If more than 10 attempts in 5 minutes → block the IP at the firewall
4. Check whether any attempt *succeeded* after the failures — search auth logs for `Accepted` entries from the same IP
5. If a login succeeded → escalate, treat as full compromise
6. If no login succeeded → document the IP, close the incident
7. Add the IP to the blocklist and enrich with threat intel

## Playbook: Credential Stuffing (RULE-004 — T1110.004)

1. Identify the source IP and the number of 401 responses on `/login`
2. Check whether any attempt returned 200 (successful login)
3. If a successful login is found → notify the account owner, reset credentials, review account activity
4. If no success → rate-limit or block the IP at the WAF
5. Check whether the credentials appear in known breach corpora — that indicates a targeted replay

## Playbook: SQL Injection / Scanner (RULE-009 / RULE-012 — T1190)

1. Identify the target endpoint and payload from the request
2. Determine whether the application is actually vulnerable to the payload
3. If exploitation is confirmed → preserve evidence, isolate the affected host, engage development for a patch
4. Block the source IP and check for follow-on requests from the same fingerprint
5. Review WAF logs for other attempts against the same endpoint

## Playbook: Invalid User Login (RULE-002 — T1078)

1. Check whether the targeted username corresponds to a real account
2. Look for other attempts from the same IP — cluster by time
3. If the IP shows multiple attempts → possible username enumeration, block it
4. If isolated → log and monitor

## Playbook: Sudo Authentication Failure (RULE-003 — T1078)

1. Identify the UID that failed the sudo attempt
2. Check whether prior successful logins from that account were legitimate
3. Multiple failures from the same UID → likely privilege escalation attempt, lock the account and investigate
4. Single failure → likely fat-finger, log and monitor

## Playbook: Segfault (RULE-006 — T1203)

1. Identify which process crashed and on which host
2. Check whether the crash followed a network request — correlation matters
3. Pull the core dump if available
4. Check whether the crash is repeatable — a deterministic crash on crafted input is an exploitation signature
5. Notify the system owner and patch or isolate the affected service

## Playbook: Sensitive File Access (RULE-014 — T1552.001)

1. Determine whether the request actually returned the file (200 vs 403/404)
2. If credentials were exposed → rotate them immediately, then investigate access scope
3. If blocked → verify the web server config and monitor for variant paths (`/.env.bak`, `/.env.local`)

## Playbook: Port Scan / Masscan (RULE-008 / RULE-013 — T1046)

1. Identify the scan source and the ports probed
2. Cross-check whether any probed service is actually exposed
3. Reconnaissance is often the prelude to exploitation — watch the same source for follow-on targeted attacks
4. Block at the firewall and record the source in the watchlist

---

## Severity levels

| Level    | Response time | Who to notify     |
|----------|---------------|-------------------|
| Low      | 24 hours      | Log only          |
| Medium   | 4 hours       | SOC team          |
| High     | 30 minutes    | SOC + management  |
| Critical | Immediate     | All stakeholders  |
