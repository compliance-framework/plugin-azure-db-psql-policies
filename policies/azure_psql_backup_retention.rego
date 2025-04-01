package compliance_framework.template.azure._deny_no_automatic_backups

# METADATA
# title: Ensure automatic backups are enabled for Azure PostgreSQL databases
# description: Verifies that automatic backups are enabled for Azure PostgreSQL databases to ensure data protection and compliance.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_RMG_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-framework-2
    # Class: SAMA_CSF_1.0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "5.2.2", # Backup and Disaster Recovery
        "statement-ids": [
            "3", # Ensure automated backup systems are implemented.
        ],
    },
    # SAMA IT Governance Framework v1.0
    # https://rulebook.sama.gov.sa/en/it-governance-framework
    # Class: SAMA_ITGF_1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.3.4", # IT Governance for Backup and Continuity
        "statement-ids": [
            "2", # Ensure that backup systems are in place and functional.
        ],
    },
    # SAMA Risk Management Guidelines v1.0
    # https://www.sama.gov.sa/en/RulesInstructions/RiskManagement
    # Class: SAMA_RMG_1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.2.1", # Backup Risk Management
        "statement-ids": [
            "1", # Backup and recovery plans must be managed as a risk.
        ],
    },
]

violation[{
  "title": "Automatic backups are not enabled",
}] if {
  input.Properties.backup.backupRetentionDays == 0
}