# Troubleshooting Notes

## Temporary Authentication Data

This lab uses KQL `datatable()` to create controlled authentication events.

The data is temporary and exists only during the current query execution.

It is not stored as a permanent Microsoft Sentinel table.

## `AuthData` Not Found

### Problem

Running the following query separately can produce an error:

~~~kusto
AuthData
| order by TimeGenerated asc
~~~

Error:

~~~text
Failed to resolve table or column expression named 'AuthData'
~~~

### Cause

`AuthData` is a temporary KQL variable when created with `let`.

For example:

~~~kusto
let AuthData = datatable(...);
~~~

The variable exists only within that query execution.

It is not a permanent Sentinel table.

### Fix

Define the data and use it in the same query:

~~~kusto
let AuthData = datatable(
    TimeGenerated:datetime,
    UserPrincipalName:string,
    IPAddress:string,
    ResultType:int,
    ResultDescription:string,
    AppDisplayName:string,
    Location:string
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126, "Invalid username or password", "Microsoft Office", "Unknown"
];

AuthData
| order by TimeGenerated asc
~~~

## `datatable()` Data Does Not Persist

### Problem

The authentication data appears when the query is executed, but no permanent Sentinel table is created.

### Cause

`datatable()` creates temporary inline data.

It does not ingest the events into the Log Analytics workspace.

### Fix

Include the `datatable()` definition in each investigation query.

This is intentional for this lab.

## Why DCR Ingestion Was Not Used

A persistent custom table would require additional Azure configuration.

The earlier approach introduced unnecessary complexity around:

- Data Collection Rules
- Data Collection Endpoints
- Logs Ingestion API
- Azure role assignments
- Custom table creation

The lab was simplified to use `datatable()` so the focus remains on:

- KQL
- Authentication analysis
- Detection logic
- SOC investigation

## Query Works Once but Fails in a New Query

### Problem

The following works:

~~~kusto
let AuthData = datatable(
    User:string,
    Result:int
)
[
    "user1", 50126
];

AuthData
| summarize count()
~~~

But running this separately does not work:

~~~kusto
AuthData
| summarize count()
~~~

### Cause

The temporary `AuthData` definition is not available in the new query.

### Fix

Include the dataset definition in every query.

## Result Types Used in the Lab

| ResultType | Meaning |
|---:|---|
| 50126 | Invalid username or password |
| 0 | Successful authentication |

These values are part of the controlled lab dataset.

## Source IP Investigation

The main source IP associated with the failed authentication activity is:

`185.220.101.10`

The same source IP generates failed authentication attempts against multiple accounts.

This is an important pattern when investigating possible password spraying.

The lab does not contain threat intelligence, so the IP should not be classified as confirmed malicious.

## Different Source IPs for User1

User1 has authentication activity from:

- `185.220.101.10`
- `10.10.10.25`

The second authentication is associated with Hyderabad.

A source IP change should be investigated, but it does not automatically indicate malicious activity.

## Do Not Automatically Confirm Account Compromise

User1 shows the following sequence:

~~~text
Failed → Failed → Success
~~~

The sequence is suspicious, but it does not prove that the account was compromised.

The dataset does not contain:

- MFA information
- Conditional Access results
- Device information
- Sign-in risk
- User-agent information
- Endpoint telemetry
- Post-authentication activity

Additional telemetry would be required before confirming account compromise.

## Recommended Investigation Language

Use:

> The authentication pattern is suspicious and consistent with possible password spraying.

Avoid:

> The account was confirmed compromised.

## Basic KQL Test

Use the following query to confirm that `datatable()` is working:

~~~kusto
datatable(
    User:string,
    Result:int
)
[
    "user1", 50126,
    "user2", 0
]
| summarize EventCount=count() by Result
~~~

Expected result:

| Result | EventCount |
|---:|---:|
| 50126 | 1 |
| 0 | 1 |

## Troubleshooting Sequence

When a KQL query fails:

1. Confirm the `datatable()` definition is included.
2. Check that the column names match the dataset.
3. Run the dataset by itself.
4. Add investigation operators one at a time.
5. Check the KQL syntax.
6. Make sure a temporary `let` variable is not being used from another query.
