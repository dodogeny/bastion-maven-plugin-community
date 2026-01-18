# SecHive Maven Plugin

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/sechive-maven-plugin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/sechive-maven-plugin)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Proactively secure your Maven projects by identifying vulnerabilities in dependencies before they reach production.**

SecHive is a powerful, developer-friendly Maven plugin that automatically scans your project's dependencies against the National Vulnerability Database (NVD), providing actionable insights into known security issues. Trusted by development teams who prioritize security without sacrificing productivity.

---

## Why Choose SecHive?

| | Benefit |
|:---:|---|
| **Zero Configuration** | Start scanning immediately. No database setup, no complex configuration files. Add the plugin and run. |
| **Real-Time Protection** | Automatically syncs with the latest CVE data from NVD, ensuring your projects are protected against newly discovered threats. |
| **Actionable Reports** | Generate comprehensive HTML and JSON reports that clearly identify vulnerabilities, their severity, and affected dependencies. |
| **CI/CD Integration** | Seamlessly integrates with GitHub Actions, Jenkins, GitLab CI, and other popular CI/CD platforms. |
| **Enterprise Ready** | Scales from individual projects to large multi-module enterprise applications. |

---

## Quick Start Guide

Get your first security scan running in three simple steps:

### Step 1: Add the Plugin

Include SecHive in your `pom.xml`:

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>sechive-maven-plugin</artifactId>
    <version>2.2.1</version>
    <executions>
        <execution>
            <goals>
                <goal>scan</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

### Step 2: Execute the Scan

```bash
mvn clean verify
```

### Step 3: Review Your Results

Navigate to `target/sechive-reports/` to view your comprehensive security report.

> **Note:** The initial scan downloads the complete vulnerability database, which may require additional time. Subsequent scans are significantly faster as they only fetch incremental updates.

### Optimize Your Scan Performance

Obtain a free API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key) to accelerate database synchronization by up to 5x:

```bash
mvn sechive:scan -Dsechive.nvd.apiKey=YOUR_API_KEY
```

---

## Configuration Examples

### Enforce Security Standards

Configure SecHive to fail builds when vulnerabilities exceed your threshold:

```xml
<configuration>
    <failOnError>true</failOnError>
    <severityThreshold>HIGH</severityThreshold>
</configuration>
```

### Enable Vulnerability Tracking

Maintain a historical record of vulnerabilities for trend analysis:

```xml
<configuration>
    <communityStorageMode>JSON_FILE</communityStorageMode>
    <reportFormats>HTML,JSON</reportFormats>
</configuration>
```

### Multi-Module Project Support

Enable comprehensive scanning across all modules:

```xml
<configuration>
    <enableMultiModule>true</enableMultiModule>
</configuration>
```

---

## Complete Configuration Reference

### Core Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `skip` | `false` | Bypass security scanning for this execution |
| `failOnError` | `false` | Terminate build when vulnerabilities are detected |
| `severityThreshold` | `MEDIUM` | Minimum severity level to trigger build failure (CRITICAL, HIGH, MEDIUM, LOW) |
| `reportFormats` | `HTML,JSON` | Output formats for vulnerability reports |
| `outputDirectory` | `target/sechive-reports` | Destination directory for generated reports |

### Storage Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `communityStorageMode` | `IN_MEMORY` | Storage strategy: `IN_MEMORY` for ephemeral scans, `JSON_FILE` for persistent tracking |
| `jsonFilePath` | `target/.../vulnerabilities.json` | File path for vulnerability history persistence |

### Scanner Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `nvdApiKey` | - | NVD API key for enhanced synchronization performance |
| `enableMultiModule` | `false` | Enable scanning across all modules in multi-module projects |
| `scannerTimeout` | `300000` | Maximum scan duration in milliseconds |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'

    - name: Run Security Scan
      run: mvn sechive:scan -Dsechive.nvd.apiKey=${{ secrets.NVD_API_KEY }}

    - name: Upload Reports
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: security-reports
        path: target/sechive-reports/
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'mvn sechive:scan -Dsechive.nvd.apiKey=${NVD_API_KEY}'
            }
        }
    }
    post {
        always {
            publishHTML([
                reportDir: 'target/sechive-reports',
                reportFiles: 'sechive-report.html',
                reportName: 'Security Report'
            ])
        }
    }
}
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: maven:3.9-eclipse-temurin-21
  script:
    - mvn sechive:scan -Dsechive.nvd.apiKey=${NVD_API_KEY}
  artifacts:
    paths:
      - target/sechive-reports/
```

---

## Edition Comparison

| Feature | Community (Free) | Professional ($149/mo) |
|---------|------------------|------------------------|
| **Vulnerability Detection** | Full NVD coverage | Full NVD coverage + 3-6x faster scans |
| **Report Formats** | HTML, JSON | HTML, JSON, PDF, SARIF, SBOM |
| **Notifications** | - | Slack, Teams, Discord, Email |
| **Advanced Features** | - | License compliance, predictive updates, Docker mode |
| **Storage Options** | In-memory, JSON | In-memory, JSON, PostgreSQL, MySQL |
| **Support** | Community | Priority support (24-hour response) |

[Explore Professional Features](https://dodogeny.github.io/sechive-maven-plugin/)

---

## Troubleshooting

**Extended Duration on Initial Scan**

The first scan downloads the complete NVD database containing 300,000+ CVE records. This is a one-time operation. Obtain a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) to significantly reduce download time.

**"Unsupported class version" Error**

SecHive 2.x requires Java 21 or later. Verify your Java version:
```bash
java -version
```

**Database Synchronization Issues After Upgrade**

Clear the cached database and reinitialize:
```bash
rm -rf ~/.m2/repository/org/owasp/dependency-check-utils/
mvn sechive:scan
```

---

## Migration Guide (v1.x to v2.x)

<details>
<summary>Migrating from Bastion? Click to expand.</summary>

SecHive was previously known as "Bastion" in v1.x. The following changes apply:

| Component | v1.x (Bastion) | v2.x (SecHive) |
|-----------|----------------|----------------|
| Artifact ID | `bastion-maven-community-plugin` | `sechive-maven-plugin` |
| Commands | `mvn bastion:scan` | `mvn sechive:scan` |
| Properties | `bastion.*` | `sechive.*` |
| Report Directory | `target/bastion-reports/` | `target/sechive-reports/` |

</details>

---

## Disclaimer

This project's codebase was developed with the assistance of **Claude**, Anthropic's AI assistant. All features have been **thoroughly battle-tested** through extensive automated testing, real-world production usage, and continuous integration pipelines to ensure reliability and prevent regressions.

We maintain comprehensive test coverage and adhere to industry best practices, guaranteeing consistent performance across diverse environments and use cases.

---

## Get Started Today

Securing your Maven dependencies has never been easier. Add SecHive to your project and gain immediate visibility into potential vulnerabilities. Whether you're working on a personal project or managing enterprise applications, SecHive provides the security insights you need to ship with confidence.

**Ready to secure your project?** Add the plugin to your `pom.xml` and run your first scan today.

---

## Support & Resources

- **Issue Tracker:** [Report bugs or request features](https://github.com/dodogeny/sechive-maven-plugin/issues)
- **Contact:** it.dodogeny@gmail.com
- **Documentation:** [Complete documentation](https://dodogeny.github.io/sechive-maven-plugin/)

---

**Requirements:** Java 21+, Maven 3.6+

**License:** Apache 2.0

**Foundation:** Built on [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
