# Bastion Maven Plugin Community

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/bastion-maven-community-plugin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/bastion-maven-community-plugin)
[![Build Status](https://github.com/dodogeny/bastion-maven-community-plugin/workflows/CI/badge.svg)](https://github.com/dodogeny/bastion-maven-community-plugin/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A comprehensive Maven security plugin for automated vulnerability scanning, CVE detection, and software supply chain security. The **Community Edition** provides powerful open-source vulnerability scanning built on OWASP Dependency-Check 12.1.3 with intelligent auto-update and trend analysis. The **Commercial Edition** extends this with advanced features including predictive update analysis, license compliance checks, risk scoring, and enterprise-grade reporting.

📖 **[Quick Start Guide](distribution/src/main/resources/docs/QUICKSTART.md)** - Get up and running in 5 minutes!

## Features

- **Zero-Configuration Setup**: Automatically downloads and updates the NVD database - no manual setup required
- **Intelligent Auto-Update**: Always uses the latest CVE data with smart incremental updates
- **Automated CVE Detection**: Scans project dependencies against the National Vulnerability Database (NVD)
- **Smart NVD Caching**: Reduces scan times from 8-13 minutes to 2-3 minutes with intelligent cache management
- **Historical Trend Analysis**: Track vulnerability trends over time with JSON file storage
- **Detailed CVE Tracking**: See exactly which CVEs were resolved, introduced, or remain pending between scans
- **Multi-Module Support**: Scan complex Maven projects with multiple modules
- **Multiple Report Formats**: HTML and JSON reports with graphical dependency trees
- **CI/CD Integration**: Compatible with GitHub Actions, Jenkins, GitLab CI, and Azure DevOps
- **Performance Metrics**: Detailed scan statistics with bottleneck identification

## Quick Start

### Prerequisites

- **Java**: JDK 21 or higher (required for v1.1.0+, v1.2.1 recommended)
- **Maven**: 3.6.0 or higher
- **Memory**: 1GB+ RAM for large projects
- **Internet**: First-time NVD database download (~317,000 CVEs)

### Installation

Add the plugin to your `pom.xml`:

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.2.8-rc2</version>
    <executions>
        <execution>
            <goals>
                <goal>scan</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

### Run Your First Scan

**Option 1: Via Build Lifecycle (Recommended)**
```bash
# Run as part of Maven verify phase
mvn clean verify
```

**Option 2: Direct Plugin Execution**
```bash
# Basic scan
mvn io.github.dodogeny:bastion-maven-community-plugin:1.2.8-rc2:scan

# With NVD API key (recommended for faster downloads)
mvn io.github.dodogeny:bastion-maven-community-plugin:1.2.8-rc2:scan \
  -Dbastion.nvd.apiKey=YOUR_NVD_API_KEY

# Short form (after first use)
mvn bastion-maven-community-plugin:scan
```

**Option 3: IDE Integration**
- **IntelliJ IDEA**: Right-click on `pom.xml` → Run Maven → `clean verify`
- **Eclipse**: Right-click project → Run As → Maven build → Goals: `clean verify`
- **VS Code**: Maven sidebar → Lifecycle → verify

**⏱️ First Run**: Downloads NVD database (~318,000 CVEs, 5-10 min with API key)
**🚀 Subsequent Runs**: Uses cached database (30-60 seconds)
**📊 Reports**: Generated in `target/bastion-reports/`

## What's New in v1.2.8-rc2

### 🔄 Dynamic Version Management & Enhanced Release Workflow
- **Single Source of Truth**: Version managed in parent POM `<revision>` property
- **Automated Documentation**: All version references update automatically via Maven resource filtering
- **Enhanced Release Process**: Comprehensive GitHub Actions workflow with:
    - Pre-flight validation (version format, tag checking, CHANGELOG validation)
    - Automated testing and artifact verification with SHA-256 checksums
    - Professional release notes with commit categorization (Features, Bug Fixes, Docs)
    - Email notifications to distribution list after successful deployment
    - Maven Central deployment with GPG signing
    - Detailed release summaries with job status tracking

### Enhanced JAR-Level Vulnerability Analysis
- **📦 Detailed Dependency Tracking**: Comprehensive tracking of vulnerable JAR dependencies across scans
    - **✅ Resolved JARs**: See exactly which JARs are no longer vulnerable with all fixed CVEs
    - **🆕 New Vulnerable JARs**: Identify newly introduced dependencies with complete CVE details
    - **⏳ Pending Vulnerable JARs**: Track ongoing vulnerabilities with partial resolution detection
        - Know which CVEs were fixed within still-vulnerable JARs
        - Identify new CVEs discovered in previously vulnerable dependencies
        - Severity breakdown (Critical, High, Medium, Low) for each JAR

### Improved Console Output
- **📊 Enhanced Logging**: Beautiful formatted output boxes with detailed JAR analysis
- **🎯 Prioritized Display**: Top vulnerable JARs sorted by severity (Critical → High → Medium → Low)
- **📈 Trend Insights**: Actionable insights about dependency and vulnerability changes
- **💡 Smart Analysis**: Detailed trend interpretation for in-memory database mode

### Comprehensive Test Coverage
- **🧪 New Test Suites**: 14 new test cases ensuring reliability
- **✅ 100% Coverage**: All new JAR analysis features thoroughly tested
- **🔍 Complex Scenarios**: Tests for partial resolutions and multi-JAR states

### Version History
- **📚 CHANGELOG.md**: Comprehensive version history with detailed change tracking
- **🔗 Clickable Navigation**: Easy access to specific version details
- **📖 Upgrade Guides**: Clear instructions for migrating between versions

[See the complete CHANGELOG](distribution/src/main/resources/docs/CHANGELOG.md)


### General Core Improvements
- **💾 Automatic Memory Management**: Intelligent MAVEN_OPTS configuration for OWASP subprocesses
    - Automatically allocates 3GB heap for NVD database downloads
    - Automatically allocates 2GB heap for vulnerability scanning
    - Eliminates Out of Memory errors during long-running scans
    - No manual memory configuration required
- **🎉 Zero-Configuration Setup**: Automatic NVD database initialization - no manual commands required!
- **🔄 Intelligent Auto-Update**: Always uses the latest CVE data with automatic incremental updates
- **OWASP Dependency-Check 12.1.3**: Latest vulnerability detection engine with improved accuracy
- **Java 21 Required**: Modern runtime for improved performance (breaking change from v1.0.x)
- **Database Corruption Fix**: Resolved H2 database issues affecting earlier versions
- **CVSS v4.0 Support**: Enhanced parsing of newer vulnerability data
- **Dynamic Path Detection**: Eliminates hardcoded version paths

### Performance Enhancements
- **Automatic Memory Allocation**: Plugin intelligently configures heap size for OWASP processes
- Automatic database initialization on first run (no manual setup needed)
- Smart incremental updates - downloads only new CVE data, not the entire database
- Smart NVD caching with sub-second validation for test environments
- Improved concurrent processing for faster dependency analysis
- Memory optimization for large enterprise projects
- Enhanced NVD API 2.0 integration with better rate limiting
- **Prevents OOM Kills**: No more exit code 137 errors during long scans

### User Experience Improvements
- **🎯 Contextual Enterprise Suggestions**: Intelligent upgrade prompts at key moments
    - Appears when approaching storage limits or at usage milestones
    - Shows relevant features based on your project scale and findings
    - Non-intrusive with built-in frequency control
- **📊 Enhanced HTML Reports**: Visual comparison banner showcasing Enterprise features
- **💡 Smart Feature Discovery**: Learn about advanced capabilities when you need them
- **📈 Usage Tracking**: Milestone messages at 5th, 10th, and 20th scans

### Trend Analysis Enhancements
- **📈 Detailed CVE Changes**: Track exactly which vulnerabilities changed between scans
    - ✅ **Resolved CVEs**: Shows CVEs that were fixed since the last scan
    - 🆕 **New CVEs Introduced**: Highlights newly detected vulnerabilities
    - ⏳ **Pending CVEs**: Count of unresolved vulnerabilities
- **📊 Overall Vulnerability Trends**: Visual trend indicators showing changes in total, critical, high, medium, and low severity counts
- **🔗 NVD Links**: Direct links to NIST NVD for each CVE with severity badges

### Architecture Improvements
- **🏗️ ScanEngine Architecture**: New orchestration layer for scanning workflow
    - `ScanEngine` interface for unified scanning API
    - `DefaultScanEngine` implementation with processor chains
    - `ScanEngineFactory` with preset configurations (default, lightweight, CI/CD, development)
- **🔧 Design Patterns**: Improved code quality with enterprise patterns
    - `ProcessorChain` for vulnerability processing pipeline
    - `ScanEventPublisher` for event-driven notifications
    - Builder pattern for flexible engine configuration

### Migration Notes
- Upgrading from v1.0.x requires Java 21+ (breaking change)
- First scan will automatically download NVD database (~317,000 CVEs, 20-30 minutes with API key)
- H2 database files from v1.0.x are not compatible - delete `~/.bastion/nvd-cache` before upgrading
- No manual `mvn dependency-check:update-only` commands needed anymore!
- **Memory configuration is now automatic** - no need to set MAVEN_OPTS manually

## Usage

### Basic Commands

```bash
# Simple scan with default settings
mvn bastion:scan

# With NVD API key for faster scans
mvn bastion:scan -Dbastion.nvd.apiKey=YOUR_API_KEY

# JSON file storage for trend analysis
mvn bastion:scan -Dbastion.community.storageMode=JSON_FILE

# Multi-module projects
mvn bastion:scan -Dbastion.multiModule.enabled=true

# Fail build on critical vulnerabilities
mvn bastion:scan -Dbastion.failOnError=true -Dbastion.severityThreshold=CRITICAL
```

### Configuration Examples

#### Basic Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.2.8-rc2</version>
    <configuration>
        <skip>false</skip>
        <failOnError>true</failOnError>
        <severityThreshold>MEDIUM</severityThreshold>
        <reportFormats>HTML,JSON</reportFormats>
    </configuration>
</plugin>
```

#### JSON Storage with Trend Analysis

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.2.8-rc2</version>
    <configuration>
        <communityStorageMode>JSON_FILE</communityStorageMode>
        <jsonFilePath>${project.build.directory}/security/vulnerabilities.json</jsonFilePath>
        <outputDirectory>${project.build.directory}/security</outputDirectory>
        <reportFormats>HTML,JSON</reportFormats>
    </configuration>
</plugin>
```

#### Multi-Module Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.2.8-rc2</version>
    <configuration>
        <enableMultiModule>true</enableMultiModule>
        <communityStorageMode>JSON_FILE</communityStorageMode>
        <scannerTimeout>600000</scannerTimeout>
        <severityThreshold>HIGH</severityThreshold>
    </configuration>
</plugin>
```

#### NVD API Key Configuration (Recommended)

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.2.8-rc2</version>
    <configuration>
        <!-- NVD API key for faster database downloads and updates -->
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>

        <!-- Auto-update is always enabled for latest CVE data -->
        <!-- Smart caching and incremental updates are automatic -->
        <!-- Memory allocation is automatic - no MAVEN_OPTS needed -->
    </configuration>
</plugin>
```

## NVD API Key Setup

Get a free NVD API key for better performance and reliability:

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Complete registration and verify email
3. Configure the API key:

**Environment Variable (Recommended)**
```bash
export NVD_API_KEY="your-api-key"
mvn bastion:scan -Dbastion.nvd.apiKey=${NVD_API_KEY}
```

**Maven Settings (~/.m2/settings.xml)**
```xml
<settings>
    <profiles>
        <profile>
            <id>bastion</id>
            <properties>
                <nvd.api.key>your-api-key</nvd.api.key>
            </properties>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>bastion</activeProfile>
    </activeProfiles>
</settings>
```

**Benefits:**
- 5x faster scans (2000 requests/30s vs 50/30s rate limit)
- More reliable with reduced rate limiting
- Access to latest vulnerability data

## Storage Options

### In-Memory Database (Default)

Best for quick scans and CI/CD pipelines.

```bash
mvn bastion:scan -Dbastion.community.storageMode=IN_MEMORY
```

**Pros:** Zero setup, fastest performance, auto cleanup
**Cons:** No persistence, no trend analysis

### JSON File Storage

Best for historical tracking and trend analysis.

```bash
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.storage.jsonFilePath=/path/to/vulnerabilities.json
```

**Pros:** Persistent storage, trend analysis, version control friendly, human readable
**Cons:** Slightly slower than in-memory

## Intelligent Auto-Update System

Bastion automatically manages the NVD database with zero configuration required:

### How It Works

1. **First-Time Setup**: Automatically downloads the complete NVD database (~317,000 CVEs) on first scan
2. **Smart Updates**: OWASP Dependency-Check intelligently checks for new CVE data on every scan
3. **Incremental Downloads**: Only downloads new/updated CVEs, not the entire database
4. **Always Current**: Ensures you're always scanning against the latest vulnerability data

### What You See

**First Run (no database exists):**
```
[INFO] 🔧 First-time setup: Initializing NVD database...
[INFO] ⏱️  This will take 20-30 minutes (one-time only)
[INFO] 🔄 Future scans will automatically check for incremental updates
[INFO] Downloading 317,332 CVE records...
[INFO] ✅ NVD database initialized successfully!
```

**Subsequent Runs (database exists):**
```
[INFO] ✅ NVD database found (age: 2 days) - OWASP will check for updates automatically
[INFO] 🔄 Auto-update enabled: OWASP will check for latest NVD data
[INFO] 🔑 Using NVD API key for faster updates
[INFO] Checking for new CVE data...
[INFO] Downloaded 47 new CVE records
[INFO] Analyzing dependencies... (2-3 minutes)
```

### NVD Database Location

View/clear database cache:
- Linux/Mac: `~/.m2/repository/org/owasp/dependency-check-utils/12.1.3/data/`
- Windows: `%USERPROFILE%\.m2\repository\org\owasp\dependency-check-utils\12.1.3\data\`

Force fresh download (if needed):
```bash
rm -rf ~/.m2/repository/org/owasp/dependency-check-utils/
mvn bastion:scan  # Will automatically re-download
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'

    - name: Cache Maven dependencies
      uses: actions/cache@v3
      with:
        path: ~/.m2
        key: ${{ runner.os }}-m2-${{ hashFiles('**/pom.xml') }}

    - name: Run Security Scan
      env:
        NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      run: |
        mvn bastion:scan \
          -Dbastion.nvd.apiKey=${NVD_API_KEY} \
          -Dbastion.failOnCritical=true
        # v1.1.1+ automatically manages memory - no MAVEN_OPTS needed

    - name: Upload Reports
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: security-reports
        path: target/security/
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        NVD_API_KEY = credentials('nvd-api-key')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    mvn bastion:scan \
                      -Dbastion.nvd.apiKey=${NVD_API_KEY} \
                      -Dbastion.failOnCritical=true
                '''
            }
        }
    }

    post {
        always {
            publishHTML([
                reportDir: 'target/security',
                reportFiles: 'bastion-report.html',
                reportName: 'Security Scan Report'
            ])
        }
    }
}
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: maven:3.8-openjdk-11
  script:
    - mvn bastion:scan
        -Dbastion.nvd.apiKey=${NVD_API_KEY}
        -Dbastion.failOnCritical=true
  artifacts:
    when: always
    paths:
      - target/security/
    expire_in: 30 days
```

## Configuration Reference

### Core Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | boolean | `false` | Skip scan execution |
| `failOnError` | boolean | `false` | Fail build on vulnerabilities |
| `severityThreshold` | string | `MEDIUM` | Minimum severity to fail build (CRITICAL, HIGH, MEDIUM, LOW) |
| `reportFormats` | string | `HTML,JSON` | Report formats to generate |
| `outputDirectory` | string | `${project.build.directory}/security` | Report output directory |

### Storage Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `communityStorageMode` | string | `IN_MEMORY` | Storage mode (IN_MEMORY, JSON_FILE) |
| `jsonFilePath` | string | `${project.build.directory}/security/vulnerabilities.json` | JSON file location |
| `purgeBeforeScan` | boolean | `false` | Purge data before scanning |

### NVD Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `nvdApiKey` | string | - | NVD API key (highly recommended for faster downloads/updates) |

**Note**: Auto-update is always enabled to ensure you're scanning against the latest CVE data. The plugin automatically:
- Downloads the complete NVD database on first run
- Checks for and downloads only new CVE data on subsequent runs
- Uses OWASP Dependency-Check's built-in intelligence for update decisions

### Multi-Module Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enableMultiModule` | boolean | `false` | Enable multi-module scanning |
| `scannerTimeout` | int | `300000` | Scanner timeout in milliseconds |

### Purge Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `purge.force` | boolean | `false` | Force purge without confirmation |
| `purge.projectOnly` | boolean | `false` | Purge only current project data |
| `purge.olderThanDays` | int | `0` | Purge data older than N days |
| `purge.dryRun` | boolean | `false` | Preview purge without executing |

## Data Management

### Purge Operations

```bash
# Preview what would be purged
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.dryRun=true

# Purge with confirmation
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true

# Force purge without confirmation
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.force=true

# Purge data older than 30 days
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.olderThanDays=30
```

## Troubleshooting

### Upgrade Issues (v1.0.x to v1.1.x)

**"Unsupported major.minor version" Error**

This indicates Java 8 is being used. v1.1.x requires Java 21+:

```bash
# Check Java version
java -version

# Set JAVA_HOME to Java 21+
export JAVA_HOME=/path/to/java21
mvn bastion:scan
```

**Database Connection Errors After Upgrade**

v1.1.x uses OWASP Dependency-Check 12.1.3 with a new H2 database format. Delete old database:

```bash
# Remove old cache (if upgrading from v1.0.x)
rm -rf ~/.bastion/nvd-cache

# Remove OWASP database (if experiencing connection issues)
rm -rf ~/.m2/repository/org/owasp/dependency-check-utils/

# Run scan - will automatically re-download
mvn bastion:scan
```

**Out of Memory Errors (Fixed in v1.1.0+)**

If you're using an older version and experiencing OOM errors (exit code 137) or scans hanging for hours:

```bash
# Upgrade to v1.2.8-rc2 (or v1.1.0+) which includes automatic memory management
# Update your pom.xml to version 1.2.8-rc2
```

v1.1.0+ and v1.2.8-rc2 automatically configure memory allocation for OWASP subprocesses:
- **NVD Database Downloads**: 3GB heap automatically allocated
- **Vulnerability Scanning**: 2GB heap automatically allocated
- **No manual MAVEN_OPTS configuration needed**

The plugin logs will show:
```
[INFO] 💾 Setting MAVEN_OPTS=-Xmx3g for database initialization
[INFO] 💾 Setting MAVEN_OPTS=-Xmx2g for OWASP subprocess
```

**First Scan Takes 20-30 Minutes**

The first scan automatically downloads the complete NVD database (~317,000 CVE records). This is normal and expected behavior. The plugin will display:

```
[INFO] 🔧 First-time setup: Initializing NVD database...
[INFO] ⏱️  This will take 20-30 minutes (one-time only)
[INFO] 🔄 Future scans will automatically check for incremental updates
[INFO] 💾 Setting MAVEN_OPTS=-Xmx3g for database initialization
```

**To speed this up:**
- Get a free NVD API key from https://nvd.nist.gov/developers/request-an-api-key
- Add `-Dbastion.nvd.apiKey=YOUR_KEY` to reduce download time from hours to 20-30 minutes

**Subsequent scans** will only download new CVE data (typically seconds to minutes), not the entire database.

### Performance Optimization

1. **Use NVD API key**: Get free key from https://nvd.nist.gov/developers/request-an-api-key (reduces initial download from hours to 20-30 minutes)
2. **Automatic updates**: Already enabled by default - no configuration needed
3. **Use JSON storage**: Enables trend analysis without sacrificing performance
4. **Let it run once**: The first scan downloads the full database, subsequent scans only download new CVEs
5. **Monitor logs**: Watch for "NVD database found (age: X days)" to see automatic update behavior

## Scan Statistics

Bastion provides detailed performance metrics:

```
📊 Bastion Scan Statistics
📦 JARs Scanned: 127
🔍 CVEs Found: 23 (8 unique)
🎯 CVEs with Exploits: 5
📈 Average CVSS Score: 6.7

⏱️ Performance:
├─ Initialization: 1.2s
├─ Dependency Resolution: 3.4s
├─ Vulnerability Analysis: 12.8s
├─ Report Generation: 2.1s
└─ Total: 19.5s

💾 Resources:
├─ Peak Memory: 384 MB
├─ Processing Speed: 6.5 JARs/second
└─ Cache Hit Rate: 78%
```

## Enterprise Edition

Bastion Maven Plugin offers an **Enterprise Edition** designed for teams and organizations that need advanced security capabilities, predictive intelligence, and comprehensive license compliance management. Built for production environments where security, compliance, and governance are critical.

### Key Enterprise Features

**🔮 Predictive Update Analysis** *(Enterprise Exclusive)*
Intelligent dependency update recommendations powered by real-time Maven Central analysis:
- **Smart Version Analysis**: Automatically analyzes 5+ newer versions of vulnerable dependencies
- **CVE Impact Forecasting**: Predicts which CVEs would be resolved vs. introduced by each update
- **Risk-Based Recommendations**: Categorizes updates as "Safe" (reduces CVEs, no new issues) vs "Risky" (may introduce new vulnerabilities)
- **Comprehensive Reporting**: HTML, PDF, and JSON reports with detailed upgrade paths
- **Zero Configuration**: Works out-of-the-box with your existing dependencies
- **Maven Central Integration**: Real-time version availability and metadata lookup
- **Configurable Analysis Depth**: COMPREHENSIVE, STANDARD, or QUICK scanning modes
- **Pre-release Handling**: Option to include/exclude beta versions in analysis

*Example Output:*
```
🔮 Predictive Update Analysis Summary
├─ Dependencies Analyzed: 127
├─ Safe Updates Available: 23 (will resolve 47 CVEs)
├─ Updates with Risks: 8 (require manual review)
└─ No Safe Updates: 12 (wait for patches)

🏆 Top Recommendations:
  • spring-security-core: 5.7.1 → 6.2.1 (resolves 8 CVEs)
  • jackson-databind: 2.13.3 → 2.16.1 (resolves 12 CVEs)
  • commons-fileupload: 1.4 → 1.5 (resolves 2 CVEs)
```

**⚖️ License Compliance & Risk Analysis** *(Enterprise Exclusive)*
Comprehensive license management to prevent legal issues and ensure regulatory compliance:
- **Automatic License Detection**: Scans all project dependencies and detects licenses from manifests, POMs, and metadata
- **Policy Enforcement Engine**:
    - Define approved licenses (allowlist)
    - Block prohibited licenses (blocklist)
    - Require OSI-approved licenses only
    - Custom policy presets (DEFAULT, PERMISSIVE, STRICT)
- **License Compatibility Matrix**: Validates compatibility between 150+ license pairs (e.g., GPL + Apache, MIT + BSD)
- **Risk Scoring System**: Automated risk assessment (0-100 scale) with compliance percentage
- **Comprehensive Reporting**: TEXT, HTML, JSON, CSV, and PDF formats for audits and stakeholders
- **20+ License Support**: Apache-2.0, MIT, GPL-2.0/3.0, LGPL-2.1/3.0, BSD-2/3-Clause, MPL-2.0, ISC, EPL-1.0/2.0, CDDL-1.0, AGPL-3.0, and more
- **Violation Management**: CRITICAL and HIGH severity violations with configurable build failure policies
- **Unknown License Handling**: Flag or block dependencies with unclear licensing

*Policy Examples:*
```xml
<!-- Strict GPL-incompatible policy -->
<configuration>
    <policyPreset>STRICT</policyPreset>
    <blockedLicenses>
        <license>GPL-3.0</license>
        <license>AGPL-3.0</license>
    </blockedLicenses>
    <requireOsiApproved>true</requireOsiApproved>
    <failOnViolation>true</failOnViolation>
</configuration>
```

**📊 Advanced Reporting & Export Formats**
- **PDF Reports**: Executive-ready documents for stakeholders, auditors, and compliance teams
- **SARIF Format**: GitHub Security tab integration for automated security alerts
- **CycloneDX SBOM**: Software Bill of Materials for supply chain compliance (NTIA, EO 14028)
- **Custom Templates**: Branded reports with company logos and styling
- **Trend Graphs**: Visual charts showing vulnerability trends over time
- **Comparison Reports**: Side-by-side current vs. predictive analysis

**💾 Enterprise Storage & Scalability**
- **Persistent Databases**: PostgreSQL, MySQL, H2 support with automatic schema management
- **Unlimited Scan History**: Store years of scan data for trend analysis and compliance audits
- **Unlimited Projects**: No 50-project limit (Community restriction removed)
- **Cross-Project Analytics**: Organization-wide security dashboards
- **Data Retention Policies**: Configurable retention with automatic archival

**📧 Team Collaboration & Notifications**
- **Email Notifications**: Automatic alerts on CRITICAL/HIGH findings with detailed CVE information
- **Configurable Triggers**: Set thresholds for when to notify (e.g., only CRITICAL vulnerabilities)

**🔍 Advanced Analysis Features**
- **False Positive Suppression**: Mark and track false positives with justifications (audit trail)
- **Custom Severity Thresholds**: Override default CVSS scores based on your environment
- **Exploitability Analysis**: Identify CVEs with known exploits in the wild
- **Dependency Tree Visualization**: Interactive graphs showing vulnerability propagation paths
- **Transitive Dependency Analysis**: Identify which top-level dependencies introduce vulnerabilities

**⚡ Enterprise Support & SLA**
- **24-Hour Response SLA**: Priority email support with guaranteed response times
- **Direct Access to Security Experts**: Consult with security professionals on vulnerability remediation
- **Custom Integration Support**: Help with CI/CD pipelines, custom workflows, and automation
- **Security Advisory Updates**: Early notification of critical vulnerabilities

### Community vs Enterprise

| Feature                      | Community Edition     | Enterprise Edition       |
|------------------------------|-----------------------|--------------------------|
| **Core Scanning**            |                       |                          |
| Vulnerability Detection      | ✅ Full (OWASP 12.1.3) | ✅ Full (OWASP 12.1.3)    |
| CVE Database Auto-Update     | ✅ Automatic           | ✅ Automatic              |
| Multi-Module Support         | ✅ Yes                 | ✅ Yes                    |
| HTML/JSON Reports            | ✅ Yes                 | ✅ Yes                    |
| Trend Analysis (CVE Changes) | ✅ Basic               | ✅ Advanced               |
| **Predictive Intelligence**  |                       |                          |
| Predictive Update Analysis   | ❌ No                  | ✅ Yes                    |
| Safe Update Recommendations  | ❌ No                  | ✅ Yes                    |
| CVE Impact Forecasting       | ❌ No                  | ✅ Yes                    |
| Maven Central Integration    | ❌ No                  | ✅ Real-time              |
| **License Compliance**       |                       |                          |
| License Detection            | ❌ No                  | ✅ Automatic              |
| Policy Enforcement           | ❌ No                  | ✅ Approve/Block Lists    |
| License Compatibility Matrix | ❌ No                  | ✅ 150+ Pairs             |
| Risk Scoring                 | ❌ No                  | ✅ 0-100 Scale            |
| Compliance Reporting         | ❌ No                  | ✅ TEXT/HTML/JSON/CSV/PDF |
| **Advanced Reporting**       |                       |                          |
| PDF Reports                  | ❌ No                  | ✅ Yes                    |
| SARIF (GitHub Security)      | ❌ No                  | ✅ Yes                    |
| CycloneDX SBOM               | ❌ No                  | ✅ Yes                    |
| Custom Templates             | ❌ No                  | ✅ Yes                    |
| **Collaboration**            |                       |                          |
| Email Notifications          | ❌ No                  | ✅ CRITICAL/HIGH Alerts   |
| **Storage & Scale**          |                       |                          |
| Storage Mode                 | 💾 In-Memory/JSON     | ✅ PostgreSQL/MySQL/H2    |
| Scan History                 | ✅ 10 per project      | ✅ Unlimited              |
| Maximum Projects             | ✅ 50 projects         | ✅ Unlimited              |
| Data Retention               | ⏰ Temporary           | ✅ Permanent              |
| Cross-Project Analytics      | ❌ No                  | ✅ Yes                    |
| **Support & SLA**            |                       |                          |
| Support Channel              | 📖 Community/GitHub   | ⚡ Priority Email         |
| Response Time                | ⏰ Best Effort         | ✅ 24-Hour SLA            |
| Custom Integrations          | ❌ No                  | ✅ Yes                    |
| **Pricing**                  |                       |                          |
| Cost                         | 🆓 **Free Forever**   | 💰 **$89/month**         |
| 14-Day Trial                 | N/A                   | ✅ Available               |

### Upgrade Messaging

The Community Edition may display contextual upgrade suggestions at key moments:
- When approaching storage limits (45+ projects, 8+ scans per project)
- After detecting significant vulnerabilities (50+ findings)
- When requesting enterprise features (PDF/SARIF reports)
- At usage milestones (5th, 10th, 20th scan)

These messages are **non-intrusive** and designed to inform users about features that could benefit their workflow. You can safely ignore them and continue using the full vulnerability detection capabilities of the Community Edition.

### Enterprise Pricing & Trial

**Monthly Subscription**: $89/month
- ✅ Full feature access
- ✅ Unlimited projects and scan history
- ✅ PostgreSQL/MySQL database support
- ✅ PDF/SARIF/SBOM exports
- ✅ License compliance & risk analysis
- ✅ Priority support (24-hour SLA)

**14-Day Free Trial**:
- No credit card required
- Full enterprise feature access
- Cancel anytime
- → **[Start Trial](https://bastion-plugin.lemonsqueezy.com/)**

### How to Integrate Enterprise Edition

After subscribing, you'll receive a license key. Here's how to configure it:

#### Step 1: Add Enterprise Plugin to pom.xml

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-enterprise-plugin</artifactId>
    <version>1.1.0</version>
    <executions>
        <execution>
            <goals>
                <goal>scan</goal>
            </goals>
            <phase>verify</phase>
        </execution>
    </executions>
    <configuration>
        <!-- License Configuration -->
        <licenseKey>${env.BASTION_LICENSE_KEY}</licenseKey>

        <!-- NVD API Key -->
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>

        <!-- Database Configuration (PostgreSQL/MySQL) -->
        <databaseUrl>jdbc:postgresql://localhost:5432/bastion</databaseUrl>
        <databaseUsername>${env.DB_USERNAME}</databaseUsername>
        <databasePassword>${env.DB_PASSWORD}</databasePassword>

        <!-- Report Configuration -->
        <reportFormats>HTML,JSON,PDF,SARIF</reportFormats>
        <outputDirectory>${project.build.directory}/bastion-reports</outputDirectory>

        <!-- Email Notifications -->
        <emailEnabled>true</emailEnabled>
        <emailRecipients>security@yourcompany.com</emailRecipients>
        <emailOnlyForCritical>true</emailOnlyForCritical>
        
    </configuration>
</plugin>
```

#### Step 2: Set Environment Variables

```bash
# License Key (provided after subscription)
export BASTION_LICENSE_KEY=your-license-key-here

# NVD API Key (optional but recommended)
export NVD_API_KEY=your-nvd-api-key

# Database Credentials
export DB_USERNAME=bastion_user
export DB_PASSWORD=secure_password

```

#### Step 3: Initialize Database

Enterprise Edition requires a PostgreSQL or MySQL database:

**PostgreSQL**:
```sql
CREATE DATABASE bastion;
CREATE USER bastion_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE bastion TO bastion_user;
```

**MySQL**:
```sql
CREATE DATABASE bastion;
CREATE USER 'bastion_user'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON bastion.* TO 'bastion_user'@'localhost';
FLUSH PRIVILEGES;
```

#### Step 4: Run Your First Enterprise Scan

```bash
# Run security scan with enterprise features
mvn clean verify

# Or run directly
mvn bastion-maven-enterprise-plugin:scan

# Run predictive update analysis
mvn bastion-maven-enterprise-plugin:predictive-analysis

# Run license compliance check
mvn bastion-maven-enterprise-plugin:license-check
```

**Enterprise Goals Available:**
- `scan` - Full vulnerability scanning with PDF/SARIF/SBOM exports
- `predictive-analysis` - Analyze dependency updates and CVE impact
- `license-check` - License compliance and risk analysis

#### Step 5: Verify Enterprise Features

Check that enterprise features are working:

1. **Database**: Verify scan results are persisted in your database
2. **PDF Reports**: Check `target/bastion-reports/` for PDF exports
3. **Predictive Analysis**: Run `mvn bastion-maven-enterprise-plugin:predictive-analysis` and review recommendations in `target/bastion-predictive-reports/`
4. **License Compliance**: Run `mvn bastion-maven-enterprise-plugin:license-check` and review reports in `target/bastion-reports/`
5. **Email Notifications**: Verify emails are received for CRITICAL vulnerabilities

#### Step 6: Configure Advanced Features (Optional)

Add predictive analysis and license checking to your build lifecycle:

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-enterprise-plugin</artifactId>
    <version>1.1.0</version>
    <executions>
        <!-- Vulnerability Scanning -->
        <execution>
            <id>vulnerability-scan</id>
            <goals>
                <goal>scan</goal>
            </goals>
            <phase>verify</phase>
        </execution>

        <!-- Predictive Update Analysis -->
        <execution>
            <id>predictive-analysis</id>
            <goals>
                <goal>predictive-analysis</goal>
            </goals>
            <phase>verify</phase>
            <configuration>
                <analysisDepth>COMPREHENSIVE</analysisDepth>
                <maxVersionsToAnalyze>5</maxVersionsToAnalyze>
                <onlyVulnerableDependencies>true</onlyVulnerableDependencies>
                <reportFormats>HTML,PDF,JSON</reportFormats>
            </configuration>
        </execution>

        <!-- License Compliance Check -->
        <execution>
            <id>license-check</id>
            <goals>
                <goal>license-check</goal>
            </goals>
            <phase>verify</phase>
            <configuration>
                <policyPreset>DEFAULT</policyPreset>
                <failOnViolation>true</failOnViolation>
                <reportFormat>TEXT,HTML,JSON,PDF</reportFormat>
            </configuration>
        </execution>
    </executions>
</plugin>
```

**📖 Enterprise Documentation**:
- Predictive Analysis: [Configuration Guide](../bastion-maven-plugin-enterprise/PREDICTIVE_ANALYSIS_GUIDE.md)
- License Compliance: [Full Guide](../bastion-maven-plugin-enterprise/LICENSE_COMPLIANCE_GUIDE.md)

### Enterprise Support

Need help with integration or have questions?
- **Email**: it.dodogeny@gmail.com
- **Response Time**: 4-hour SLA
- **Documentation**: Enterprise-specific guides included with subscription
- **Custom Integration**: Available for enterprise customers

## Compatibility Matrix

| Bastion Version | Java Requirement | OWASP Dependency-Check | Auto-Update | Memory Management | JAR Analysis | Status |
|-----------------|------------------|------------------------|-------------|-------------------|--------------|--------|
| 1.2.8-rc2 | Java 21+ | 12.1.3 | ✅ Automatic | ✅ Automatic | ✅ Enhanced | **Recommended** |
| 1.1.0 | Java 21+ | 12.1.3 | ✅ Automatic | ✅ Automatic | ✅ Basic | Stable |
| 1.0.x | Java 8+ | 10.0.4 | ❌ Manual | ⚠️ Manual MAVEN_OPTS | ❌ None | Legacy (security patches only) |

## Support

### Community Support
- **Email**: it.dodogeny@gmail.com
- **GitHub Issues**: https://github.com/dodogeny/bastion-maven-plugin-community/issues
- **Documentation**: See this README and inline configuration comments

### Getting Help
- Check the troubleshooting section above
- Search existing GitHub issues
- Email us at it.dodogeny@gmail.com with questions
- Create a new issue with scan logs and configuration

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Acknowledgments

Built on [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/), the industry-standard open source vulnerability scanner.