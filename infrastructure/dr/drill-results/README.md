# DR drill results

`restore_verification.sh` writes one JSON record per weekly drill here
(`drill-<timestamp>.json`) and appends a row to `SUMMARY.md`. The GitHub
Actions workflow uploads this directory as a 365-day artifact.

Do not edit the records by hand; the runbook in
[`docs/runbooks/disaster-recovery.md`](../../docs/runbooks/disaster-recovery.md)
explains how to read RTO/RPO and what to investigate when a target is missed.
