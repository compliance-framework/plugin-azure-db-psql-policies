package compliance_framework.template.azure._deny_public_subnet

# METADATA
# title: Ensure RDS instances are not deployed in public subnets
# description: Verifies that RDS instances are not deployed in public subnets to maintain network security and integrity.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-framework-2
    # Class: SAMA_CSF_1.0
    #
    # 3.3.8: Infrastructure Security
    # https://rulebook.sama.gov.sa/en/338-infrastructure-security-0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.8", # Infrastructure Security
        "statement-ids": [
            "6.e", # Segmentation of networks
        ],
    },
]

violation[{
  "title": "RDS instance is deployed in a public subnet",
}] if {
  input.Properties.network.publicNetworkAccess == "Enabled"
}