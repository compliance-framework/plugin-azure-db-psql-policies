package compliance_framework.template.azure._deny_single_az

# METADATA
# title: Ensure RDS instances are deployed across multiple availability zones
# description: Verifies that RDS instances are configured for high availability by being deployed across multiple availability zones.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf
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
  "title": "RDS instance is not Multi-AZ",
}] if {
  input.Properties.highAvailability.mode == "Disabled"
}