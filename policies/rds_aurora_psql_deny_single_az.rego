package compliance_framework.template.azure._deny_single_az

violation[{
  "title": "RDS instance is not Multi-AZ",
}] if {
  input.Properties.highAvailability.mode == "Disabled"
}