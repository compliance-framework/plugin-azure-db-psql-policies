package compliance_framework.deny_no_automatic_backup

title := "Azure PostgreSQL Automatic Backups Configured"
description := "Azure PostgreSQL should have automatic backups configured with a retention period greater than 0 days."

labels := {
  "severity": "high",
  "category": "disaster_recovery",
}

violation[{}] if {
  input.Properties.backup.backupRetentionDays == 0
}