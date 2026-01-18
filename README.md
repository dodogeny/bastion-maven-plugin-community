# SecHive Maven Plugin

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/sechive-maven-plugin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/sechive-maven-plugin)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Find security vulnerabilities in your Maven dependencies before they become a problem.**

SecHive automatically scans your project's dependencies against the National Vulnerability Database (NVD) and tells you which ones have known security issues.

## What You Get

- **Drop it in and go** - No database setup, no manual configuration. Just add the plugin and run.
- **Always up-to-date** - Automatically downloads the latest CVE data so you're protected against new threats.
- **Clear answers** - HTML reports that show exactly what's vulnerable and how severe it is.
- **CI/CD friendly** - Works with GitHub Actions, Jenkins, GitLab, and more.

## Get Started in 2 Minutes

**Step 1:** Add this to your `pom.xml`:

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

**Step 2:** Run your build:

```bash
mvn clean verify
```

**Step 3:** Check your reports in `target/sechive-reports/`

That's it! Your first scan will take 20-30 minutes to download the vulnerability database. After that, scans take just a few minutes.

### Want faster scans?

Get a free API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key) - it makes database downloads 5x faster:

```bash
mvn sechive:scan -Dsechive.nvd.apiKey=YOUR_API_KEY
```

---

## Common Configurations

### Fail the build on vulnerabilities

```xml
<configuration>
    <failOnError>true</failOnError>
    <severityThreshold>HIGH</severityThreshold>
</configuration>
```

### Track vulnerabilities over time

```xml
<configuration>
    <communityStorageMode>JSON_FILE</communityStorageMode>
    <reportFormats>HTML,JSON</reportFormats>
</configuration>
```

### Multi-module projects

```xml
<configuration>
    <enableMultiModule>true</enableMultiModule>
</configuration>
```

---

## All Configuration Options

### Basic Settings

| Option | Default | What it does |
|--------|---------|--------------|
| `skip` | `false` | Skip the scan entirely |
| `failOnError` | `false` | Fail the build if vulnerabilities are found |
| `severityThreshold` | `MEDIUM` | Minimum severity to trigger failure (CRITICAL, HIGH, MEDIUM, LOW) |
| `reportFormats` | `HTML,JSON` | Which report formats to generate |
| `outputDirectory` | `target/sechive-reports` | Where to put reports |

### Storage

| Option | Default | What it does |
|--------|---------|--------------|
| `communityStorageMode` | `IN_MEMORY` | `IN_MEMORY` for quick scans, `JSON_FILE` to track history |
| `jsonFilePath` | `target/.../vulnerabilities.json` | Where to store vulnerability history |

### Scanning

| Option | Default | What it does |
|--------|---------|--------------|
| `nvdApiKey` | - | Your NVD API key for faster scans |
| `enableMultiModule` | `false` | Scan all modules in a multi-module project |
| `scannerTimeout` | `300000` | How long to wait (in milliseconds) before timing out |

---

## Using with CI/CD

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

### Jenkins

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

## Free vs Professional

| | Free | Professional ($149/mo) |
|---|---|---|
| **Scanning** | Full vulnerability detection | Same + 3-6x faster |
| **Reports** | HTML, JSON | + PDF, SARIF, SBOM |
| **Alerts** | - | Slack, Teams, Discord, Email |
| **Extras** | - | License compliance, predictive updates, Docker mode |
| **Storage** | In-memory, JSON | + PostgreSQL, MySQL |
| **Support** | Community | 24-hour response |

[Learn more about Professional](https://dodogeny.github.io/sechive-maven-plugin/)

---

## Troubleshooting

**"First scan is taking forever"**
That's normal - it's downloading 300,000+ CVE records. Get a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) to speed it up. This only happens once.

**"Unsupported class version" error**
SecHive 2.x needs Java 21+. Check with `java -version`.

**"Database connection error" after upgrading**
Clear the old database and try again:
```bash
rm -rf ~/.m2/repository/org/owasp/dependency-check-utils/
mvn sechive:scan
```

---

## Migrating from Bastion (v1.x)?

<details>
<summary>Click to expand migration guide</summary>

We renamed from "Bastion" to "SecHive" in v2.0:

| Changed | From | To |
|---------|------|-----|
| Artifact | `bastion-maven-community-plugin` | `sechive-maven-plugin` |
| Commands | `mvn bastion:scan` | `mvn sechive:scan` |
| Properties | `bastion.*` | `sechive.*` |
| Reports | `target/bastion-reports/` | `target/sechive-reports/` |

</details>

---

## Get Help

- **Found a bug?** [Open an issue](https://github.com/dodogeny/sechive-maven-plugin/issues)
- **Questions?** Email us at it.dodogeny@gmail.com
- **Documentation:** [Full docs](https://dodogeny.github.io/sechive-maven-plugin/)

---

**Requirements:** Java 21+, Maven 3.6+

**License:** Apache 2.0

Built on [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
