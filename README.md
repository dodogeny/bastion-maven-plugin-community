# Bastion Maven Plugin Community

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/bastion-maven-community-plugin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/bastion-maven-community-plugin)
[![Build Status](https://github.com/dodogeny/bastion-maven-community-plugin/workflows/CI/badge.svg)](https://github.com/dodogeny/bastion-maven-community-plugin/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Maven plugin for automated vulnerability scanning and CVE detection in your dependencies. Built on OWASP Dependency-Check 11.1.0 with enhanced performance, caching, and trend analysis capabilities.

## Features

- **Automated CVE Detection**: Scans project dependencies against the National Vulnerability Database (NVD)
- **Smart NVD Caching**: Reduces scan times from 8-13 minutes to 2-3 minutes with intelligent cache management
- **Historical Trend Analysis**: Track vulnerability trends over time with JSON file storage
- **Multi-Module Support**: Scan complex Maven projects with multiple modules
- **Multiple Report Formats**: HTML and JSON reports with graphical dependency trees
- **CI/CD Integration**: Compatible with GitHub Actions, Jenkins, GitLab CI, and Azure DevOps
- **Performance Metrics**: Detailed scan statistics with bottleneck identification

## Quick Start

### Prerequisites

- **Java**: JDK 11 or higher (required for v1.1.0+)
- **Maven**: 3.6.0 or higher
- **Memory**: 1GB+ RAM for large projects

### Installation

Add the plugin to your `pom.xml`:

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.1.0</version>
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
# Basic scan
mvn bastion:scan

# With NVD API key (recommended for better performance)
mvn bastion:scan -Dbastion.nvd.apiKey=YOUR_NVD_API_KEY
```

Reports will be generated in `target/security/` directory.

## What's New in v1.1.0

### Core Improvements
- **OWASP Dependency-Check 11.1.0**: Latest vulnerability detection engine
- **Java 11+ Required**: Modern runtime for improved performance (breaking change)
- **Database Corruption Fix**: Resolved H2 database issues affecting earlier versions
- **CVSS v4.0 Support**: Enhanced parsing of newer vulnerability data
- **Dynamic Path Detection**: Eliminates hardcoded version paths

### Performance Enhancements
- Smart NVD caching with sub-second validation for test environments
- Improved concurrent processing for faster dependency analysis
- Memory optimization for large enterprise projects
- Enhanced NVD API 2.0 integration with better rate limiting

### Migration Notes
- Upgrading from v1.0.x requires Java 11+
- First scan will re-download NVD database (2-4GB, 5-15 minutes)
- H2 database files from v1.0.x are not compatible

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
    <version>1.1.0</version>
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
    <version>1.1.0</version>
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
    <version>1.1.0</version>
    <configuration>
        <enableMultiModule>true</enableMultiModule>
        <communityStorageMode>JSON_FILE</communityStorageMode>
        <scannerTimeout>600000</scannerTimeout>
        <severityThreshold>HIGH</severityThreshold>
    </configuration>
</plugin>
```

#### Smart Caching Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.1.0</version>
    <configuration>
        <autoUpdate>true</autoUpdate>
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
        <smartCachingEnabled>true</smartCachingEnabled>
        <cacheValidityHours>6</cacheValidityHours>
        <cacheDirectory>${user.home}/.bastion/nvd-cache</cacheDirectory>
        <enableRemoteValidation>false</enableRemoteValidation>
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

## Smart NVD Caching

Bastion uses intelligent caching to avoid unnecessary NVD database downloads:

### How It Works

1. **Local Cache Validation**: Fast local-only checks for unit tests
2. **Remote Change Detection**: Queries NVD servers only when enabled
3. **Threshold-Based Updates**: Downloads only if record count changes by 5%+ (configurable)

### Usage

```bash
# Enable smart caching
mvn bastion:scan \
  -Dbastion.nvd.apiKey=your-api-key \
  -Dbastion.autoUpdate=true

# Configure cache validity (default: 6 hours)
mvn bastion:scan \
  -Dbastion.nvd.apiKey=your-api-key \
  -Dbastion.autoUpdate=true \
  -Dbastion.cache.validity.hours=3

# Enable remote validation for production
mvn bastion:scan \
  -Dbastion.nvd.apiKey=your-api-key \
  -Dbastion.autoUpdate=true \
  -Dbastion.enableRemoteValidation=true
```

### Performance Impact

**Without caching:**
```
[INFO] Downloading NVD database... (5-10 minutes)
[INFO] Analyzing dependencies... (2-3 minutes)
[INFO] Total: 8-13 minutes
```

**With caching (cache hit):**
```
[INFO] NVD cache is valid - skipping download
[INFO] Analyzing dependencies... (2-3 minutes)
[INFO] Total: 2-3 minutes
```

### Cache Management

View cache location:
- Linux/Mac: `~/.bastion/nvd-cache/`
- Windows: `%USERPROFILE%\.bastion\nvd-cache\`

Clear cache:
```bash
rm -rf ~/.bastion/nvd-cache
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
        java-version: '11'
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
| `nvdApiKey` | string | - | NVD API key |
| `autoUpdate` | boolean | `true` | Auto-update NVD database |
| `smartCachingEnabled` | boolean | `true` | Enable smart caching |
| `cacheValidityHours` | int | `6` | Cache validity in hours |
| `enableRemoteValidation` | boolean | `false` | Enable remote NVD validation |

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

### Upgrade Issues (v1.0.x to v1.1.0)

**"Unsupported major.minor version" Error**

This indicates Java 8 is being used. v1.1.0 requires Java 11+:

```bash
# Check Java version
java -version

# Set JAVA_HOME to Java 11+
export JAVA_HOME=/path/to/java11
mvn bastion:scan
```

**Database Connection Errors After Upgrade**

v1.1.0 uses a different H2 database format. Delete old database:

```bash
rm -rf ~/.bastion/nvd-cache
mvn bastion:scan  # Will download fresh database
```

**First Scan Takes Very Long**

The first scan needs to download the NVD database (2-4GB). This is normal and takes 5-15 minutes depending on connection speed. Subsequent scans will be much faster with caching.

### Performance Optimization

1. **Use NVD API key**: Get free key from https://nvd.nist.gov/developers/request-an-api-key
2. **Enable smart caching**: Set `autoUpdate=true` and configure `cacheValidityHours`
3. **Use JSON storage**: Enables trend analysis without sacrificing performance
4. **Adjust cache validity**: Longer for CI/CD (12-24h), shorter for development (2-6h)
5. **Monitor logs**: Watch for cache hit/miss messages to optimize settings

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

| Bastion Version | Java Requirement | OWASP Dependency-Check | Status |
|-----------------|------------------|------------------------|--------|
| 1.1.0+ | Java 11+ | 11.1.0 | Current |
| 1.0.x | Java 8+ | 10.0.4 | Legacy (security patches only) |

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
