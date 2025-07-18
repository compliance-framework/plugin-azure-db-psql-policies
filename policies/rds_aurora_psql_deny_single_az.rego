package compliance_framework.deny_single_az

violation[{}] if {
  input.Properties.highAvailability.mode == "Disabled"
}

title := "Azure PostgreSQL Single AZ Deployment Denied"
description := "Azure PostgreSQL should not be deployed in a single availability zone."
labels := {
  "severity": "medium",
  "category": "availability",
}