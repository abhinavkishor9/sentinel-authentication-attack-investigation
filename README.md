# Sentinel Authentication Attack Investigation

Practical Microsoft Sentinel KQL lab for investigating suspicious authentication activity.

## Concept

This lab focuses on identifying authentication attack patterns by analyzing:

- Failed authentication attempts
- Common source IP addresses
- Multiple targeted accounts
- Repeated authentication failures
- Successful authentication after failures
- Changes in source IP
- User authentication timelines

The lab uses controlled KQL data, so it does not require live authentication telemetry.

## Scenario

A single source IP generates multiple failed authentication attempts against different user accounts.

One of the targeted accounts later authenticates successfully from the same source IP.

The same user then authenticates successfully from a different internal IP address.

The investigation determines whether this pattern is consistent with password spraying and identifies the additional evidence that would be needed for further investigation.

## Objectives

- Analyze authentication events using KQL
- Identify failed authentication activity
- Find the source IP generating the failures
- Identify targeted accounts
- Build a user authentication timeline
- Correlate failed and successful logins
- Identify suspicious authentication patterns
- Identify evidence gaps

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

## Investigation Findings

- 7 failed authentication attempts originated from `185.220.101.10`
- 4 different accounts were targeted
- `user1`, `user2`, and `user3` each had two failures
- `user4` had one failure
- `user1` successfully authenticated from the same source IP after the failures
- `user1` later authenticated from `10.10.10.25`
- The activity is suspicious but does not independently prove account compromise

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

## Key Learning

The main SOC pattern demonstrated in this lab is:

**One source IP → multiple accounts → repeated failures → successful authentication**

The next investigation step would be to correlate the authentication activity with identity, endpoint, MFA, Conditional Access, and threat intelligence data.
