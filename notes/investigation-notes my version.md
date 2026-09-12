# Investigation Notes

## Dataset

The lab uses controlled authentication telemetry created with KQL `datatable()`.

The dataset contains:

- 9 authentication events
- 7 failed authentication attempts
- 2 successful authentications
- 4 targeted accounts
- 2 source IP addresses

## Initial Observation

The first observation is a concentration of failed authentication events from:

`185.220.101.10`

All seven failed events originate from this address.

The failures are distributed across four accounts instead of being concentrated on a single account.

## Failed Authentication Pattern

| User | Failed Attempts | Source IP |
|---|---:|---|
| user1@sentinellab.local | 2 | 185.220.101.10 |
| user2@sentinellab.local | 2 | 185.220.101.10 |
| user3@sentinellab.local | 2 | 185.220.101.10 |
| user4@sentinellab.local | 1 | 185.220.101.10 |

The source IP therefore targeted multiple accounts.

This pattern is more consistent with password spraying than repeated brute-force attempts against a single account.

## Source IP Analysis

The failed authentication source was:

`185.220.101.10`

Observed:

- Failed attempts: 7
- Targeted accounts: 4
- Application: Microsoft Office
- Location: Unknown

The source IP should not automatically be classified as malicious based only on this dataset.

Threat intelligence would be required to establish whether the IP has known malicious associations.

## User1 Investigation

User1 was selected for deeper investigation because the account experienced multiple failures followed by a successful authentication.

### User1 Timeline

| Time | Result | Source IP | Location |
|---|---|---|---|
| 10:01 | Failed | 185.220.101.10 | Unknown |
| 10:02 | Failed | 185.220.101.10 | Unknown |
| 10:08 | Success | 185.220.101.10 | Unknown |
| 10:10 | Success | 10.10.10.25 | Hyderabad |

The important sequence is:

`Failed → Failed → Success`

from the same external source IP.

A second successful authentication then appears from:

`10.10.10.25`

with the location recorded as:

`Hyderabad`

## Authentication Correlation

The successful authentication from `185.220.101.10` is significant because this address was responsible for the earlier failed attempts.

However, the available evidence does not establish why the successful authentication occurred.

Possible explanations include:

- A correct password was eventually supplied
- The account credentials were compromised
- The activity was legitimate but initially mistyped
- The simulated dataset does not contain enough context to distinguish these possibilities

## Password Spraying Assessment

The activity is **consistent with password spraying** because:

1. One source IP generated multiple failed authentications.
2. Multiple user accounts were targeted.
3. The attempts occurred within a short time period.
4. One targeted account later authenticated successfully.

The evidence supports a suspicious authentication pattern, but it does not prove that a password spray attack succeeded.

## Evidence Strength

### Confirmed

- Seven authentication failures occurred.
- All seven failures originated from `185.220.101.10`.
- Four accounts were targeted.
- User1 successfully authenticated from `185.220.101.10`.
- User1 later authenticated from `10.10.10.25`.

### Plausible

- The activity is consistent with password spraying.
- The successful authentication may indicate valid credentials were obtained.

### Unknown

- Whether the source IP is malicious.
- Whether the successful login was performed by an attacker.
- Whether MFA was completed.
- Whether the user intentionally authenticated from the external IP.
- Whether any activity occurred after authentication.

## Evidence Gaps

The dataset does not provide:

- MFA results
- Conditional Access results
- Device details
- User-agent information
- Sign-in risk
- Authentication method
- Endpoint telemetry
- Post-authentication activity
- Threat intelligence results
- User confirmation

These gaps prevent the activity from being classified as a confirmed account compromise.

## SOC Classification

**Classification:** Suspicious Authentication Activity

**Severity:** Medium

**Confidence:** Medium

**Potential Technique:** Password Spraying

**MITRE ATT&CK:** T1110.003 - Password Spraying

