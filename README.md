# Bastion Maven Plugin - Community Edition

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/mu.dodogeny/bastion-maven-plugin-community/badge.svg)](https://maven-badges.herokuapp.com/maven-central/mu.dodogeny/bastion-maven-plugin-community)
[![Build Status](https://github.com/dodogeny/bastion-maven-plugin-community/workflows/CI/badge.svg)](https://github.com/dodogeny/bastion-maven-plugin-community/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Your Maven project's fortified defense against security vulnerabilities! 🛡️

Bastion Maven Plugin Community Edition is an open-source vulnerability scanning solution that integrates seamlessly into your Maven build pipeline. This community edition provides essential security scanning capabilities with HTML/JSON reporting and in-memory storage.

## 🏗️ Community Edition Architecture

Bastion Community Edition is built as a clean multi-module Maven project:

- **📊 vulnerability-db**: In-memory database layer for vulnerability storage
- **🔍 scanner-core**: OWASP Dependency-Check integration for vulnerability scanning  
- **📋 reporting**: HTML and JSON report generation with dependency trees
- **🔌 plugin**: Maven plugin implementation with comprehensive statistics

## 🚀 Quick Start

### Prerequisites
- **Java**: JDK 8 or higher
- **Maven**: 3.6.0 or higher  

### Basic Installation

Add the plugin to your `pom.xml`:

```xml
<plugin>
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-community</artifactId>
    <version>1.0.0</version>
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
# Community Edition scan
mvn mu.dodogeny:bastion-maven-plugin-community:1.0.0:scan
```

Reports will be generated in `target/bastion-reports/` directory.

## 🛠️ Available Maven Goals

```bash
# 🔍 Primary scanning goal
mvn bastion:scan

# 📄 Community Edition - JSON file storage mode
mvn bastion:scan -Dbastion.community.storageMode=JSON_FILE

# 📄 Community Edition - In-memory database mode (default)
mvn bastion:scan -Dbastion.community.storageMode=IN_MEMORY

# 🔑 NVD API key for enhanced scanning
mvn bastion:scan -Dbastion.nvd.apiKey=YOUR_NVD_API_KEY
```

## 💾 Storage Configuration

### Community Edition Storage Options

The Community Edition offers two storage modes:

#### Option 1: In-Memory Database (Default)

```xml
<plugin>
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-community</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Storage mode selection -->
        <communityStorageMode>IN_MEMORY</communityStorageMode>
    </configuration>
</plugin>
```

**Features:**
- ⚡ **Zero Setup**: No database installation required
- 🗄️ **Session Storage**: Data persists during Maven session
- 📊 **Basic Trends**: Limited trend analysis capabilities
- 🧹 **Memory Management**: Automatic cleanup when Maven session ends

#### Option 2: JSON File Storage

```xml
<plugin>
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-community</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Storage mode selection -->
        <communityStorageMode>JSON_FILE</communityStorageMode>
        <jsonFilePath>${project.build.directory}/bastion-vulnerabilities.json</jsonFilePath>
    </configuration>
</plugin>
```

**Features:**
- 📄 **File Persistence**: Data survives between scans and reboots
- 📈 **Full Trend Analysis**: Complete historical trend tracking
- 🔍 **Version Control**: JSON files can be committed for audit trails
- 🛠️ **Manual Analysis**: Human-readable format for direct inspection

## 📊 Community Edition Features

**Community Edition** (Free & Open Source):
- OWASP Dependency-Check scanner with NVD API key support
- HTML and JSON reports with graphical dependency trees
- Dedicated trend analysis report with historical tracking
- Configurable storage (in-memory database or JSON file)
- Basic performance metrics
- Multi-module scanning support

## 🏢 Enterprise Features Available

For additional enterprise features, consider upgrading to `bastion-maven-plugin-enterprise`:

**Enterprise Edition Features**:
- All Community Edition features plus:
- **Persistent H2/PostgreSQL/MySQL databases**
- **Enhanced historical trend analysis** across projects
- **PDF and SARIF report generation**
- **Advanced email notifications**
- **Real-time monitoring capabilities**
- **Enterprise support and priority assistance**

### Migration to Enterprise

To upgrade to the enterprise edition:

1. **Replace the plugin dependency**:
```xml
<plugin>
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <!-- Your existing configuration -->
</plugin>
```

2. **Contact us for enterprise licensing**: enterprise-sales@dodogeny.mu

## 📊 Reports & Analytics

### Community Edition Reports
- **HTML**: Interactive reports with graphical dependency trees and CVE documentation tables
- **JSON**: Machine-readable format with detailed vulnerability descriptions for CI/CD integration  
- **Trend Report**: Dedicated trend analysis report showing historical vulnerability patterns

### HTML Report Features

#### 🌳 **Graphical Dependency Tree**
- **Visual Tree Structure**: ASCII-based dependency hierarchy similar to `mvn dependency:tree`
- **Vulnerability Indicators**: Color-coded vulnerability counts and severity badges  
- **Direct vs Transitive**: Clear classification of dependency relationships
- **Risk Assessment**: Smart analysis of direct vs transitive vulnerability impact

```
📦 My Spring Boot Project (com.example:my-app:1.0.0)
├── org.springframework.boot:spring-boot-starter-web:2.5.0 [compile] [3] HIGH
│   📁 ~/.m2/repository/org/springframework/boot/...
├── org.apache.commons:commons-lang3:3.8.1 [compile] [1] MEDIUM  
│   📁 ~/.m2/repository/org/apache/commons/...
└── org.slf4j:slf4j-api:1.7.25 [compile] ✓ Clean
```

#### 📋 **CVE Documentation Table**  
- **Comprehensive CVE Details**: Each vulnerability with full descriptions
- **Official Links**: Clickable links to MITRE CVE database and NVD entries
- **Severity Indicators**: Color-coded severity badges and CVSS scores
- **Affected Components**: Component and version information for each CVE

## 🛠️ CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-java@v3
      with:
        java-version: '11'
        distribution: 'temurin'
    
    - name: Run Security Scan
      run: |
        mvn mu.dodogeny:bastion-maven-plugin-community:1.0.0:scan \
          -Dbastion.communityStorageMode=JSON_FILE \
          -Dbastion.failOnError=true
    
    - name: Upload Security Reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-reports
        path: target/bastion-reports/
```

## 📚 Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `failOnError` | boolean | true | Fail build on vulnerabilities |
| `severityThreshold` | String | "MEDIUM" | Minimum severity to fail on |
| `reportFormats` | String | "HTML,JSON" | Report formats to generate |
| `communityStorageMode` | String | IN_MEMORY | Storage mode (IN_MEMORY, JSON_FILE) |
| `jsonFilePath` | String | target/bastion-vulnerabilities.json | JSON storage file path |
| `nvdApiKey` | String | null | NVD API key for enhanced scanning |
| `enableMultiModule` | boolean | true | Enable multi-module scanning |
| `scannerTimeout` | int | 300000 | Scanner timeout in milliseconds |

## 🔐 Security & Privacy

Bastion Community Edition is designed with security-first principles:

- **No Data Exfiltration**: All vulnerability data stays within your infrastructure  
- **Encrypted Communication**: TLS/SSL for all external API calls
- **Audit Logging**: Complete audit trail of all security scanning activities
- **Open Source**: Full transparency with community-driven development

## 🆘 Support & Community

### Community Support
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/dodogeny/bastion-maven-plugin-community/issues)
- **Documentation**: [Community Wiki](https://github.com/dodogeny/bastion-maven-plugin-community/wiki)

### Enterprise Support
For enterprise features and professional support:
- **Email**: enterprise-sales@dodogeny.mu

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Bastion Maven Plugin Community Edition** - Your open source fortress against security vulnerabilities.

*Developed with ❤️ by [Dodogeny](https://dodogeny.mu) in Mauritius* 🇲🇺

---