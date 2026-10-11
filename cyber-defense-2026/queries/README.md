# KQL Query Catalog

`login-origins.kql` is adapted from the course's inbound-authentication reference and scoped to `corp-nao1-lreed` over a rolling 10-day window. It uses `DeviceLogonEvents` and `geo_info_from_ip_address()`.

The numbered files are extracted query blocks from the supplied draft report. They are preserved as investigation examples; they have not been executed or independently validated during repository publication.

| Query | Purpose |
| --- | --- |
| report-01 | MySQL destructive statements and ransom markers |
| report-02 | Host authentication context |
| report-03 | MySQL read/destruction classification |
| report-04 | Network-flow byte review |
| report-05 | Cross-table IOC sweep |
| report-06 | MySQL incident timeline |
| report-07 | Azure NSG rule changes |
| report-08 | Windows failures and successes by source IP |
| report-09 | Endpoint persistence and administrator process hunt |
| report-10 | Draft MySQL destructive-activity analytic |

## Validation requirements

- Confirm table availability, column names, retention, and UTC time windows.
- Add the appropriate host/resource filter to MySQL, Azure, and network queries before using them in a shared workspace. The original MySQL blocks do not select a host.
- In report-04, byte direction depends on actual source/destination orientation. Review each flow and its schema before calling either summed column exfiltration.
- Report-10 joins by thread ID. Production use also needs host identity, server-restart context, time correlation, and robust general-log parsing.
- Submitted SQL and missing endpoint events do not establish command success or the absence of compromise.
- `RemoteIPType == "Public"` excludes private addresses and unresolved origins; the map is a filtered view, not complete login coverage.
