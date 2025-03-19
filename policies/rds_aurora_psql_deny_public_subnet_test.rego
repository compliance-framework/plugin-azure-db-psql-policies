package compliance_framework.template.azure._deny_public_subnet

test_violation_public_subnet if {
  violation[_] with input as {
    "Properties": {
      "network": {
        "publicNetworkAccess": "Enabled"
      }
    }
  }
}