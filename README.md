# Building a SOC + Honeynet in Azure (Live Traffic)
**Analyst:** Harold L.R. Watkins · **Project period:** March 2023  
**Focus:** Azure SOC infrastructure, Sentinel monitoring, and security hardening

![Cloud Honeynet / SOC](https://i.imgur.com/ZWxe03e.jpg)

## Introduction

In this project, I built a mini honeynet in Azure and ingested log sources from various resources into a Log Analytics workspace, which Microsoft Sentinel used to build attack maps, trigger alerts, and create incidents. I compared two 24-hour observation windows: one before hardening and one after applying security controls. The reported results are shown below. The monitored metrics are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/aBDwnKb.jpg)

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/YQNa9Pp.jpg)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and other resources were deployed with public endpoints visible to the Internet without Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened to restrict access to my administrative workstation. Other resources used their built-in access controls and Private Endpoints.

## Attack Maps Before Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/1qvswSX.png)<br>
![Linux Syslog Auth Failures](https://i.imgur.com/G1YgZt6.png)<br>
![Windows RDP/SMB Auth Failures](https://i.imgur.com/ESr9Dlv.png)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
**Observation window:** March 15, 2023, 17:04:29 → March 16, 2023, 17:04:29. Time zone was not recorded in the original write-up.

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 19470
| Syslog                   | 3028
| SecurityAlert            | 10
| SecurityIncident         | 348
| AzureNetworkAnalytics_CL | 843

## Attack Maps After Hardening / Security Controls

The map queries returned no matching events during the 24-hour post-hardening window. This describes the query results for that window; it does not prove that no malicious activity occurred.

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
**Observation window:** March 18, 2023, 15:37 → March 19, 2023, 15:37. Time zone was not recorded in the original write-up.

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 8778
| Syslog                   | 25
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Findings and limitations

The reported post-hardening counts were lower across all five metrics, with zero alerts, incidents, and matching malicious-flow records in the second observation window. This is consistent with reduced exposure after hardening. The windows occurred on different days, so these results do not isolate hardening as the only cause of the change.

This repository contains the project write-up and externally hosted diagrams/screenshots. Raw logs, saved KQL, and deployable infrastructure are not included, so the reported 2023 measurements cannot be independently reproduced from this repository alone.
