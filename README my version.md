# sentinel-authentication-attack-investigation

## Concept

This lab investigates authentication activity from the custom data already ingested into your Microsoft Sentinel workspace.

Instead of pretending the data is native Entra SigninLogs, we will treat it correctly as custom authentication telemetry.

The investigation will answer:

- What authentication activity occurred?
- Which users were involved?
- Which source IPs generated activity?
- How many failures occurred?
- Were multiple accounts targeted?
- Were successful authentications observed?
- Did failures precede a successful login?
- Does the activity resemble password spraying or another authentication anomaly?

## Scenario

A series of suspicious authentication events is observed in the environment. Multiple user accounts receive failed login attempts from the same source IP, `185.220.101.10`, within a short period.

The investigation focuses on:

- Repeated failed authentication attempts
- Multiple accounts targeted by one source IP
- A successful login after failed attempts
- A change in source IP for the same user

During the investigation, `user1@sentinellab.local` is found to have two failed attempts from `185.220.101.10`, followed by a successful authentication from the same IP. A later successful authentication from `10.10.10.25` is associated with Hyderabad.

The objective is to determine whether the activity is consistent with password spraying and identify what additional telemetry would be required for further investigation.

## Objectives

- Analyze authentication activity using KQL in Microsoft Sentinel
- Identify repeated failed authentication attempts
- Identify source IPs generating authentication failures
- Determine how many user accounts are being targeted
- Identify patterns consistent with password spraying
- Correlate failed and successful authentication events
- Build a timeline for a targeted user
- Identify suspicious source IP changes
- Distinguish observed evidence from assumptions
- Document evidence gaps for further investigation
- Map the observed activity to MITRE ATT&CK

## Technologies

- Microsoft Sentinel
- KQL
- Sentinel Logs
- `datatable()`

## Lab Setup

Open:

**Microsoft Sentinel → Microsoft-Sentinel-Workspace → Logs**

Create a new query.

No permanent custom table is required.

The test authentication data is created directly inside the KQL query using `datatable()`.

> `datatable()` data is available only during the current query execution.

## Step 1 - Load the Authentication Data

Run the following query:

~~~kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:02:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:03:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:04:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:05:00Z), "user4@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:06:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:07:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:08:00Z), "user1@sentinellab.local", "185.220.101.10", 0, "Success", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:10:00Z), "user1@sentinellab.local", "10.10.10.25", 0, "Success", "Microsoft Office", "Hyderabad"
]
| order by TimeGenerated asc
~~~

## Step 2 - Understand the Data

The dataset contains:

| Field | Description |
|---|---|
| `TimeGenerated` | Authentication event time |
| `UserPrincipalName` | User involved in the authentication |
| `IPAddress` | Source IP address |
| `ResultType` | Authentication result code |
| `ResultDescription` | Authentication result |
| `AppDisplayName` | Application involved |
| `Location` | Location associated with the event |

In this lab:

- `50126` represents an invalid username or password
- `0` represents a successful authentication

## Step 3 - Count Failed and Successful Events

Run:

~~~kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:02:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:03:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:04:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:05:00Z), "user4@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:06:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:07:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:08:00Z), "user1@sentinellab.local", "185.220.101.10", 0, "Success", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:10:00Z), "user1@sentinellab.local", "10.10.10.25", 0, "Success", "Microsoft Office", "Hyderabad"
]
| summarize EventCount=count() by ResultType, ResultDescription
| order by EventCount desc
~~~

Expected result:

| ResultType | ResultDescription | Events |
|---|---|---:|
| 50126 | Invalid username or password | 7 |
| 0 | Success | 2 |

## Step 4 - Identify the Main Source IP

Run:

~~~kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:02:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:03:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:04:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:05:00Z), "user4@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:06:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:07:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:08:00Z), "user1@sentinellab.local", "185.220.101.10", 0, "Success", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:10:00Z), "user1@sentinellab.local", "10.10.10.25", 0, "Success", "Microsoft Office", "Hyderabad"
]
| where ResultType == 50126
| summarize
    FailedAttempts=count(),
    TargetedAccounts=dcount(UserPrincipalName)
    by IPAddress
| order by FailedAttempts desc
~~~

Expected:

| IPAddress | Failed Attempts | Targeted Accounts |
|---|---:|---:|
| 185.220.101.10 | 7 | 4 |

## Step 5 - Identify Targeted Accounts

Run:

~~~kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:02:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:03:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:04:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:05:00Z), "user4@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:06:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:07:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:08:00Z), "user1@sentinellab.local", "185.220.101.10", 0, "Success", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:10:00Z), "user1@sentinellab.local", "10.10.10.25", 0, "Success", "Microsoft Office", "Hyderabad"
]
| where ResultType == 50126
| summarize FailedAttempts=count()
    by UserPrincipalName
| order by FailedAttempts desc
~~~

Expected:

| User | Failed Attempts |
|---|---:|
| user1@sentinellab.local | 2 |
| user2@sentinellab.local | 2 |
| user3@sentinellab.local | 2 |
| user4@sentinellab.local | 1 |

## Step 6 - Build User1 Authentication Timeline

Run:

~~~kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:02:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:03:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:04:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:05:00Z), "user4@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:06:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:07:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:08:00Z), "user1@sentinellab.local", "185.220.101.10", 0, "Success", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:10:00Z), "user1@sentinellab.local", "10.10.10.25", 0, "Success", "Microsoft Office", "Hyderabad"
]
| where UserPrincipalName == "user1@sentinellab.local"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ResultType,
    ResultDescription,
    Location
| order by TimeGenerated asc
~~~

Expected sequence:

| Time | Result | Source IP | Location |
|---|---|---|---|
| 10:01 | Failed | 185.220.101.10 | Unknown |
| 10:02 | Failed | 185.220.101.10 | Unknown |
| 10:08 | Success | 185.220.101.10 | Unknown |
| 10:10 | Success | 10.10.10.25 | Hyderabad |

## Step 7 - Check User1 Source IPs

Run:

~~~kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:02:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:03:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:04:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:05:00Z), "user4@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:06:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:07:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:08:00Z), "user1@sentinellab.local", "185.220.101.10", 0, "Success", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:10:00Z), "user1@sentinellab.local", "10.10.10.25", 0, "Success", "Microsoft Office", "Hyderabad"
]
| where UserPrincipalName == "user1@sentinellab.local"
| summarize
    AuthenticationEvents=count(),
    SourceIPs=make_set(IPAddress)
~~~

Expected:

- Authentication events: 4
- Source IPs:
  - `185.220.101.10`
  - `10.10.10.25`

## Step 8 - Review the Full Authentication Timeline

Run:

~~~kusto
datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:02:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:03:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:04:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:05:00Z), "user4@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:06:00Z), "user2@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:07:00Z), "user3@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:08:00Z), "user1@sentinellab.local", "185.220.101.10", 0, "Success", "Microsoft Office", "Unknown",
    datetime(2026-09-11T10:10:00Z), "user1@sentinellab.local", "10.10.10.25", 0, "Success", "Microsoft Office", "Hyderabad"
]
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ResultDescription,
    Location
| order by TimeGenerated asc
~~~

## What to Look For

The important sequence is:

`185.220.101.10`

→ multiple failed logins

→ multiple accounts targeted

→ successful login for `user1`

→ later successful login from `10.10.10.25`

This pattern is consistent with a password spraying scenario.


## MITRE ATT&CK

**T1110 - Brute Force**

Possible sub-technique:

**T1110.003 - Password Spraying**

## Evidence Gaps

This lab does not contain:

- MFA status
- Conditional Access information
- Device information
- Sign-in risk
- User-agent information
- Endpoint telemetry
- Post-authentication activity
- Threat intelligence confirming the source IP is malicious

These gaps should be considered before escalating the activity as a confirmed compromise.

