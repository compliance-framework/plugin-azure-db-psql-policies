package compliance_framework.template.azure._deny_public_subnet

violation[{
  "title": "RDS instance is deployed in a public subnet",
}] if {
  input.Properties.network.publicNetworkAccess == "Enabled"
}