package compliance_framework.deny_public_subnet

violation[{}] if {
  input.Properties.network.publicNetworkAccess == "Enabled"
}

title := "Azure PostgreSQL Public Subnet Access Denied"
description := "Azure PostgreSQL should not allow public subnet access."
labels := {
  "severity": "high",
  "category": "access_control",
}