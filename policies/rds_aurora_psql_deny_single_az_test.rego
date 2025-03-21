package compliance_framework.template.azure._deny_single_az

test_violation_single_az if {
  violation[_] with input as {
    "Properties": {
      "highAvailability": {
        "mode": "Disabled"
      }
    }
  }
}