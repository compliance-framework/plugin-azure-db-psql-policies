package compliance_framework.template.azure._deny_public_subnet

# METADATA
# title: Ensure RDS instance is not deployed in a public subnet
# description: Verifies that RDS instances are not deployed in public subnets to ensure secure network isolation.
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
        "control-id": "3.1.4", # Network Isolation
        "statement-ids": [
            "1", # Ensure sensitive systems are isolated from public networks.
        ],
    },
    # SAMA IT Governance Framework v1.0
    # https://rulebook.sama.gov.sa/en/it-governance-framework
    # Class: SAMA_ITGF_1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "4.1.2", # Secure Network Design
        "statement-ids": [
            "2", # Ensure that network design prevents public exposure.
        ],
    },
    # SAMA Risk Management Guidelines v1.0
    # https://www.sama.gov.sa/en/RulesInstructions/RiskManagement
    # Class: SAMA_RMG_1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "3.2.2", # Secure Network Management
        "statement-ids": [
            "1", # Ensure network security through segmentation and isolation.
        ],
    },
]

violation[{
  "title": "RDS instance is deployed in a public subnet",
}] if {
  input.Properties.network.publicNetworkAccess == "Enabled"
}