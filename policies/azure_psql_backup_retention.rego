package compliance_framework.template.azure._deny_no_automatic_backups

# METADATA
# title: Ensure automatic backups are enabled for Azure PSQL databases
# description: Verifies that automatic backups are enabled to safeguard data integrity and availability for Azure PSQL databases.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://sama.thomsonreuters.com/en/3310-data-backup-and-recoverability
    # Class: SAMA_CSF_1.0
    #
    # 3.3.10: Data Backup and Recoverability
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.10", # Data Backup and Recoverability
        "statement-ids": [
            "1", # Define, approve, and implement a data backup management strategy.
            "2", # Ensure backup policies include considerations for backup frequency, storage, and security.
        ],
    },
]

violation[{
  "title": "Automatic backups are not enabled",
}] if {
  input.Properties.backup.backupRetentionDays == 0
}