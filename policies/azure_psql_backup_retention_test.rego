package compliance_framework.template.azure._deny_no_automatic_backups

test_violation_no_automatic_backups if {
  violation[_] with input as {
    "Properties": {
      "backup": {
        "backupRetentionDays": 0
      }
    }
  }
}