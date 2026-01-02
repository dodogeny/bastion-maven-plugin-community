# License Compliance Analysis - User Guide

## Overview

The SecHive Enterprise Edition includes comprehensive license compliance analysis to help you:

- **Detect licenses** automatically from your dependencies
- **Enforce policies** with customizable license approval/blocklists
- **Check compatibility** between different licenses in your project
- **Assess risks** with intelligent risk scoring
- **Generate reports** in multiple formats (Text, HTML, JSON, CSV)
- **Fail builds** when license violations are detected

## Quick Start

### Basic Usage

Add the license check goal to your Maven build:

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>sechive-maven-plugin-enterprise</artifactId>
    <version>@project.version@</version>
    <executions>
        <execution>
            <goals>
                <goal>license-check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

Run the license check:

```bash
mvn sechive:license-check
```

## Configuration

### Policy Presets

Three predefined policies are available:

#### 1. DEFAULT Policy (Recommended)

Balanced policy suitable for most commercial projects:

```xml
<configuration>
    <policyPreset>DEFAULT</policyPreset>
</configuration>
```

**Characteristics:**
- ✅ Approves: Apache-2.0, MIT, BSD-3-Clause, BSD-2-Clause, ISC
- ❌ Blocks: GPL-2.0, GPL-3.0, AGPL-3.0 (strong copyleft)
- ⚠️ Warns: LGPL-3.0 (weak copyleft)
- 🚫 Blocks unknown licenses

#### 2. PERMISSIVE Policy

More lenient policy for internal/open-source projects:

```xml
<configuration>
    <policyPreset>PERMISSIVE</policyPreset>
</configuration>
```

**Characteristics:**
- ✅ Allows most licenses
- ❌ Only blocks: Strong copyleft (GPL, AGPL)
- ✓ Allows unknown licenses
- ✓ Does not require OSI approval

#### 3. STRICT Policy

Restrictive policy for security-sensitive projects:

```xml
<configuration>
    <policyPreset>STRICT</policyPreset>
</configuration>
```

**Characteristics:**
- ✅ Only approves: Apache-2.0, MIT
- ❌ Blocks: All copyleft licenses (GPL, LGPL, EPL, MPL)
- ✅ Requires OSI approval
- 🚫 Blocks unknown licenses

### Custom Policy Configuration

Override defaults with custom settings:

```xml
<configuration>
    <!-- Start with a preset -->
    <policyPreset>DEFAULT</policyPreset>

    <!-- Add additional approved licenses -->
    <approvedLicenses>
        <license>EPL-2.0</license>
        <license>MPL-2.0</license>
    </approvedLicenses>

    <!-- Block specific licenses -->
    <blockedLicenses>
        <license>LGPL-3.0</license>
        <license>Commercial</license>
    </blockedLicenses>

    <!-- Policy settings -->
    <blockUnknownLicenses>true</blockUnknownLicenses>
    <requireOsiApproved>false</requireOsiApproved>
</configuration>
```

### Build Failure Configuration

Control when builds should fail:

```xml
<configuration>
    <!-- Fail build on any violation (default: true) -->
    <failOnViolation>true</failOnViolation>

    <!-- Or only fail on critical violations -->
    <failOnCriticalOnly>true</failOnCriticalOnly>

    <!-- Skip license check entirely -->
    <skip>false</skip>
</configuration>
```

### Report Configuration

Customize report generation:

```xml
<configuration>
    <!-- Enable/disable report generation -->
    <generateReport>true</generateReport>

    <!-- Report output directory -->
    <reportDirectory>${project.build.directory}/license-reports</reportDirectory>

    <!-- Report formats (comma-separated) -->
    <reportFormat>TEXT,HTML,JSON,CSV</reportFormat>
</configuration>
```

## Complete Configuration Example

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>sechive-maven-plugin-enterprise</artifactId>
    <version>@project.version@</version>
    <executions>
        <execution>
            <id>license-check</id>
            <goals>
                <goal>license-check</goal>
            </goals>
            <phase>verify</phase>
            <configuration>
                <!-- Policy Settings -->
                <policyPreset>DEFAULT</policyPreset>
                <approvedLicenses>
                    <license>Apache-2.0</license>
                    <license>MIT</license>
                    <license>BSD-3-Clause</license>
                    <license>EPL-2.0</license>
                </approvedLicenses>
                <blockedLicenses>
                    <license>GPL-3.0</license>
                    <license>AGPL-3.0</license>
                </blockedLicenses>
                <blockUnknownLicenses>true</blockUnknownLicenses>
                <requireOsiApproved>false</requireOsiApproved>

                <!-- Build Behavior -->
                <failOnViolation>true</failOnViolation>
                <failOnCriticalOnly>false</failOnCriticalOnly>

                <!-- Report Settings -->
                <generateReport>true</generateReport>
                <reportDirectory>${project.build.directory}/sechive-reports</reportDirectory>
                <reportFormat>TEXT,HTML,JSON</reportFormat>
            </configuration>
        </execution>
    </executions>
</plugin>
```

## Command Line Usage

Override configuration from command line:

```bash
# Use strict policy
mvn sechive:license-check -Dsechive.license.policyPreset=STRICT

# Don't fail on violations (just report)
mvn sechive:license-check -Dsechive.license.failOnViolation=false

# Generate only HTML report
mvn sechive:license-check -Dsechive.license.reportFormat=HTML

# Skip license check
mvn sechive:license-check -Dsechive.license.skip=true

# Require OSI-approved licenses
mvn sechive:license-check -Dsechive.license.requireOsiApproved=true
```

## Understanding Reports

### Text Report

Console-friendly format with color-coded output:

```
═══════════════════════════════════════════════════════════
              LICENSE COMPLIANCE REPORT
═══════════════════════════════════════════════════════════

Analysis Date: 2025-11-17 14:30:00
Total Dependencies: 45

┌─────────────────────────────────────────────────────────┐
│ OVERALL RISK ASSESSMENT                                  │
├─────────────────────────────────────────────────────────┤
│ Risk Score: 15/100 █░░░░░░░░░░                          │
│ Risk Level: 🟡 Low Risk                                 │
│ Compliance: 95.6%                                        │
└─────────────────────────────────────────────────────────┘

LICENSE DISTRIBUTION
───────────────────────────────────────────────────────────
  Apache-2.0          :  28 ( 62.2%) ▓▓▓▓▓▓
  MIT                 :  12 ( 26.7%) ▓▓▓
  BSD-3-Clause        :   4 (  8.9%) ▓
  LGPL-3.0            :   1 (  2.2%)
```

### HTML Report

Professional web-based report with:
- Interactive tables
- Color-coded severity levels
- Drill-down capabilities
- Print-friendly layout

Open `target/sechive-reports/license-report.html` in your browser.

### JSON Report

Machine-readable format for integration:

```json
{
  "analysisDate": "2025-11-17T14:30:00",
  "totalDependencies": 45,
  "overallRiskScore": 15,
  "riskLevel": "LOW",
  "compliancePercentage": 95.6,
  "policyViolations": [...],
  "compatibilityIssues": [...],
  "recommendations": [...]
}
```

### CSV Report

Spreadsheet-compatible format for bulk analysis:

```csv
Component,License ID,License Name,Category,OSI Approved,Has Violation
"org.apache.commons:commons-lang3:3.12.0","Apache-2.0","Apache License 2.0","PERMISSIVE",true,false
"com.fasterxml.jackson.core:jackson-databind:2.15.3","Apache-2.0","Apache License 2.0","PERMISSIVE",true,false
```

## Common License Categories

### Permissive Licenses
✅ **Low Risk** - Minimal restrictions

- Apache-2.0
- MIT
- BSD-2-Clause / BSD-3-Clause
- ISC

**Safe for:** Commercial projects, proprietary software

### Weak Copyleft
⚠️ **Medium Risk** - Source distribution required for modifications

- LGPL-2.1 / LGPL-3.0
- MPL-2.0
- EPL-1.0 / EPL-2.0
- CDDL-1.0

**Use when:** Linking is allowed without source disclosure

### Strong Copyleft
❌ **High Risk** - Derivative works must be open-sourced

- GPL-2.0 / GPL-3.0
- AGPL-3.0 (network copyleft)

**Avoid in:** Commercial/proprietary software

## Troubleshooting

### Unknown License Detected

**Problem:** Dependency has unknown or missing license information

**Solutions:**
1. Check the dependency's POM file manually
2. Check the JAR file for LICENSE files
3. Contact the library maintainer
4. Consider replacing with alternative library

### False Positives

**Problem:** License detected incorrectly

**Solution:** Override license detection:
- Create custom license mapping configuration
- Document exceptions in your policy
- Report issue to SecHive support

### Build Failures

**Problem:** Build fails due to license violations

**Solutions:**
1. Review the violation report
2. Replace violating dependencies with approved alternatives
3. Request exception approval (if justified)
4. Temporarily use `-Dsechive.license.failOnViolation=false`

## Integration with CI/CD

### Jenkins Pipeline

```groovy
stage('License Compliance') {
    steps {
        sh 'mvn sechive:license-check'

        // Publish HTML report
        publishHTML([
            reportDir: 'target/sechive-reports',
            reportFiles: 'license-report.html',
            reportName: 'License Compliance Report'
        ])
    }
}
```

### GitHub Actions

```yaml
- name: License Compliance Check
  run: mvn sechive:license-check

- name: Upload Report
  uses: actions/upload-artifact@v3
  if: always()
  with:
    name: license-report
    path: target/sechive-reports/
```

### GitLab CI

```yaml
license-check:
  script:
    - mvn sechive:license-check
  artifacts:
    reports:
      license_scanning: target/sechive-reports/license-report.json
    paths:
      - target/sechive-reports/
```

## Best Practices

1. **Run early and often**: Include license checks in every build
2. **Use appropriate policy**: Choose policy based on your business model
3. **Review regularly**: Audit licenses quarterly
4. **Document exceptions**: Track approved exceptions with justification
5. **Educate developers**: Train team on license implications
6. **Automate**: Integrate into CI/CD pipeline
7. **Keep reports**: Archive reports for compliance audits

## Support

For issues or questions:
- GitHub Issues: https://github.com/dodogeny/sechive-maven-plugin-enterprise/issues
- Email: support@sechive.io
- Documentation: https://sechive.io/docs

## License

SecHive Maven Plugin Enterprise is licensed under Apache-2.0.
This documentation is © 2025 SecHive Security.
