package compliance_framework.template.azure._deny_single_az

# METADATA
# title: Ensure RDS instances are deployed across multiple availability zones
# description: Verifies that RDS instances are deployed in more than one availability zone to ensure high availability and resiliency.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_RMG_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "5.2.1", # High Availability
        "statement-ids": [
            "2", # Ensure high availability is maintained across critical systems.
        ],
        "control-link": "https://rulebook.sama.gov.sa/en/cyber-security-framework-2#high-availability"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.2.1", # IT Availability Management
        "statement-ids": [
            "1", # Ensure critical systems are deployed across multiple availability zones.
        ],
        "control-link": "https://rulebook.sama.gov.sa/en/it-governance-framework#it-availability-management"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "2.1.1", # Resilience and Redundancy
        "statement-ids": [
            "1", # Ensure systems are designed for resilience.
        ],
        "control-link": "https://www.sama.gov.sa/en/RulesInstructions/RiskManagement#resilience-and-redundancy"
    },
]

violation[{
  "title": "RDS instance is not Multi-AZ",
}] if {
  input.Properties.highAvailability.mode == "Disabled"
}