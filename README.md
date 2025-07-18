# Azure Database for PostgreSQL Compliance Policies

This repository contains OPA/Rego policies for enforcing compliance controls on Azure Database for PostgreSQL and AWS RDS Aurora PostgreSQL resources. These policies are designed for use in Compliance Framework plugins and can be bundled, tested, and evaluated locally.

## Structure

- All policies are located in the `policies/` directory.
- Each policy file is paired with a corresponding test file (e.g., `azure_psql_backup_retention.rego` and `azure_psql_backup_retention_test.rego`).

## Testing Policies

Run all policy tests using:

```shell
opa test policies
```

## Building Policy Bundles

To bundle all policies for distribution, run:

```shell
make build
```

## Evaluating Policies Locally

You can evaluate policies against sample input using OPA. For example:

```shell
opa eval -I -b policies -f pretty "data.compliance_framework.deny_no_automatic_backup" -i input.json
```

Replace `input.json` with your test input file. Adjust the data path to match the policy you want to evaluate (see the package name in each `.rego` file).

## Writing Policies

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language. Each policy should:

- Use a descriptive package name (e.g., `azure_psql_backup_retention`).
- Define a `violation` rule that returns a list of objects describing compliance issues.
- Include a metadata section as described below.

Example:

```rego
package compliance_framework.azure_psql_backup_retention

violation[{}] if {
    input.backup_retention_days < 7
}

title := "Backup retention is lower than 7 days"
```

## Metadata

Each policy must include a metadata section as comments, starting with `# METADATA`. The metadata should be in YAML format and include at least a title and description. You may also specify controls, schedule, or other custom fields.

Example:

```rego
# METADATA
# title: Azure PostgreSQL Backup Retention
# description: Ensures backup retention is at least 7 days for compliance.
# custom:
#   controls:
#     - CF-PSQL-001
#   schedule: "0 0 * * *"
```

Additional comments can be added before or after the metadata, separated by a blank line.

## References

- [Open Policy Agent Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)

Here is an example metadata:
```opa
# your custom comment

# METADATA
# title: <your-title>
# description: <your-description>
# custom:
#   controls:
#     - <control-id>
#   schedule: "<cron-string>"

# your custom comment
```

---

## License

This repository is licensed under the terms of the GNU Affero General Public License v3.0. See the [LICENSE](LICENSE) file for details.