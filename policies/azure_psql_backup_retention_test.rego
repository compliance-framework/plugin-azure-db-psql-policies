package compliance_framework.deny_no_automatic_backup

test_violation_no_automatic_backups if {
  violation[_] with input as {
    "Properties": {
      "backup": {
        "backupRetentionDays": 0
      }
    }
  }
}