# Authentication Timeline

## Timeline

| Time | User | Source IP | Result | Location |
|---|---|---|---|---|
| 10:01 | user1@sentinellab.local | 185.220.101.10 | Failed | Unknown |
| 10:02 | user1@sentinellab.local | 185.220.101.10 | Failed | Unknown |
| 10:03 | user2@sentinellab.local | 185.220.101.10 | Failed | Unknown |
| 10:04 | user3@sentinellab.local | 185.220.101.10 | Failed | Unknown |
| 10:05 | user4@sentinellab.local | 185.220.101.10 | Failed | Unknown |
| 10:06 | user2@sentinellab.local | 185.220.101.10 | Failed | Unknown |
| 10:07 | user3@sentinellab.local | 185.220.101.10 | Failed | Unknown |
| 10:08 | user1@sentinellab.local | 185.220.101.10 | Success | Unknown |
| 10:10 | user1@sentinellab.local | 10.10.10.25 | Success | Hyderabad |

## Timeline Breakdown

### 10:01

`user1@sentinellab.local` has a failed authentication attempt from:

`185.220.101.10`

### 10:02

A second failed authentication attempt is recorded for the same user from the same IP.

### 10:03

The source IP attempts authentication against:

`user2@sentinellab.local`

This changes the pattern from a single-user attack to activity involving multiple accounts.

### 10:04

The same source IP targets:

`user3@sentinellab.local`

### 10:05

The source IP targets:

`user4@sentinellab.local`

At this point, four different accounts have been targeted.

### 10:06

`user2@sentinellab.local` receives another failed authentication attempt from the same source IP.

### 10:07

`user3@sentinellab.local` receives another failed authentication attempt from the same source IP.

### 10:08

`user1@sentinellab.local` successfully authenticates from:

`185.220.101.10`

This is important because the same IP generated the earlier failed authentication attempts.

### 10:10

`user1@sentinellab.local` successfully authenticates from:

`10.10.10.25`

The location is recorded as:

`Hyderabad`

## Key Pattern

The timeline shows:

`One source IP`

→ `Multiple accounts targeted`

→ `Repeated authentication failures`

→ `Successful authentication`

This pattern is consistent with a possible password spraying attempt.

## User1 Timeline

| Time | Result | Source IP |
|---|---|---|
| 10:01 | Failed | 185.220.101.10 |
| 10:02 | Failed | 185.220.101.10 |
| 10:08 | Success | 185.220.101.10 |
| 10:10 | Success | 10.10.10.25 |

The `10:08` successful authentication should be investigated because it follows two failures from the same source IP.

The `10:10` authentication from `10.10.10.25` provides a second source IP for the same user.

## Timeline Summary

- First observed failure: `10:01`
- Last observed event: `10:10`
- Failed authentication events: `7`
- Successful authentication events: `2`
- Accounts targeted: `4`
- Main failed-authentication source: `185.220.101.10`
- Additional User1 source: `10.10.10.25`

## Investigation Focus

The main point of the timeline is to correlate events in sequence rather than examine individual authentication events in isolation.

`185.220.101.10 → multiple accounts → repeated failures → User1 success`
