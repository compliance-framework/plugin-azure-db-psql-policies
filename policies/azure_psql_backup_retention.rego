package compliance_framework.template.azure._deny_no_automatic_backups

violation[{
  "title": "Automatic backups are not enabled",
}] if {
  input.Properties.backup.backupRetentionDays == 0
}