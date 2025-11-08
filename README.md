# Bastion Maven Plugin Community

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/bastion-maven-community-plugin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/bastion-maven-community-plugin)
[![Build Status](https://github.com/dodogeny/bastion-maven-community-plugin/workflows/CI/badge.svg)](https://github.com/dodogeny/bastion-maven-community-plugin/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Maven plugin for automated vulnerability scanning and CVE detection in your dependencies. Built on OWASP Dependency-Check 12.1.3 with enhanced performance, intelligent auto-update, and trend analysis capabilities.

## Features

- **Zero-Configuration Setup**: Automatically downloads and updates the NVD database - no manual setup required
- **Intelligent Auto-Update**: Always uses the latest CVE data with smart incremental updates
- **Automated CVE Detection**: Scans project dependencies against the National Vulnerability Database (NVD)
- **Smart NVD Caching**: Reduces scan times from 8-13 minutes to 2-3 minutes with intelligent cache management
- **Historical Trend Analysis**: Track vulnerability trends over time with JSON file storage
- **Multi-Module Support**: Scan complex Maven projects with multiple modules
- **Multiple Report Formats**: HTML and JSON reports with graphical dependency trees
- **CI/CD Integration**: Compatible with GitHub Actions, Jenkins, GitLab CI, and Azure DevOps
- **Performance Metrics**: Detailed scan statistics with bottleneck identification

## Quick Start

### Prerequisites

- **Java**: JDK 21 or higher (required for v1.1.0+)
- **Maven**: 3.6.0 or higher
- **Memory**: 1GB+ RAM for large projects
- **Internet**: First-time NVD database download (~317,000 CVEs)

### Installation

Add the plugin to your `pom.xml`:

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.1.1</version>
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

```bash
# Basic scan (automatically downloads NVD database on first run)
mvn bastion:scan

# With NVD API key (recommended for faster downloads - 20-30 min vs hours)
mvn bastion:scan -Dbastion.nvd.apiKey=YOUR_NVD_API_KEY
```

**First Run**: The initial scan will automatically download the NVD database (~317,000 CVEs, 20-30 minutes with API key). This is a one-time setup.

**Subsequent Runs**: Future scans will automatically check for and download only new CVE data (typically seconds to minutes), ensuring you always have the latest vulnerability information.

Reports will be generated in `target/bastion-reports/` directory.

## What's New in v1.1.1

### Core Improvements
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
    <version>1.1.1</version>
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
    <version>1.1.1</version>
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
    <version>1.1.1</version>
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
    <version>1.1.1</version>
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

**Out of Memory Errors (Fixed in v1.1.1)**

If you're using v1.1.0 and experiencing OOM errors (exit code 137) or scans hanging for hours:

```bash
# Upgrade to v1.1.1 which includes automatic memory management
# Update your pom.xml to version 1.1.1
```

v1.1.1+ automatically configures memory allocation for OWASP subprocesses:
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

An Enterprise Edition is in development with additional features including:
- Persistent databases (PostgreSQL, MySQL, H2)
- Email notifications for security teams
- PDF and SARIF report formats
- Predictive update analysis
- Advanced threat intelligence integration
- Enhanced performance with parallel processing

For more information or to express interest, please contact the project maintainers.

## Compatibility Matrix

| Bastion Version | Java Requirement | OWASP Dependency-Check | Auto-Update | Memory Management | Status |
|-----------------|------------------|------------------------|-------------|-------------------|--------|
| 1.1.1+ | Java 21+ | 12.1.3 | ✅ Automatic | ✅ Automatic | **Recommended** |
| 1.1.0 | Java 21+ | 12.1.3 | ✅ Automatic | ⚠️ Manual MAVEN_OPTS | Upgrade to 1.1.1+ |
| 1.0.x | Java 8+ | 10.0.4 | ❌ Manual | ⚠️ Manual MAVEN_OPTS | Legacy (security patches only) |

## Support

### Community Support
- GitHub Issues: https://github.com/dodogeny/bastion-maven-community-plugin/issues
- Documentation: See this README and inline configuration comments

### Getting Help
- Check the troubleshooting section above
- Search existing GitHub issues
- Create a new issue with scan logs and configuration

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Acknowledgments

Built on [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/), the industry-standard open source vulnerability scanner.
