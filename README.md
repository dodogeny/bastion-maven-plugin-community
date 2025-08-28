# Bastion Maven Plugin Community

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/bastion-maven-community-plugin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.dodogeny/bastion-maven-community-plugin)
[![Build Status](https://github.com/dodogeny/bastion-maven-community-plugin/workflows/CI/badge.svg)](https://github.com/dodogeny/bastion-maven-community-plugin/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Bastion Maven Plugin Community** is your Maven project's fortified defense against security vulnerabilities. This free, open-source scanner helps developers and teams maintain secure codebases through automated CVE detection, comprehensive reporting, and historical trend analysis.

> **💡 Looking for Enterprise Features?** This is the **Community Edition** with core vulnerability scanning capabilities. For advanced features like persistent databases, email notifications, PDF reports, and enterprise support, see the [Upgrade to Enterprise](#-upgrade-to-enterprise-edition) section below.

## 🏗️ Multi-Module Architecture

Bastion is built as a sophisticated multi-module Maven project with clean separation of concerns:

- **📊 vulnerability-db**: Database layer with in-memory community database and commercial H2/PostgreSQL support
- **🔍 scanner-core**: Multi-source vulnerability scanning with OWASP Dependency-Check integration  
- **📋 reporting**: Multi-format report generation with graphical dependency trees (HTML, JSON, CSV, PDF*, SARIF*)
- **🔌 plugin**: Maven plugin implementation with comprehensive statistics and licensing
- **🏢 enterprise**: Commercial features including persistent databases, licensing, email notifications, and advanced analytics

*Commercial Edition only

## 🏢 Enterprise Security Management

Bastion Maven Plugin transforms how companies manage security vulnerabilities by providing:

### 📈 **Continuous Security Monitoring**
- **Historical Vulnerability Tracking**: Track CVE trends across time to measure security posture improvements
- **Multi-Module Support**: Scan entire enterprise applications with dozens of modules simultaneously
- **Performance Optimized**: Concurrent scanning with intelligent caching for large codebases
- **Database-Driven Intelligence**: Persistent storage of vulnerability data for trend analysis and reporting
- **Real-time Performance Metrics**: Detailed scan statistics including JARs processed, CVEs found, timing breakdowns, and resource usage
- **Comprehensive Statistics Display**: View scan performance with bottleneck identification and optimization recommendations

### 🔔 **Intelligent Alert System**
- **Email Notifications**: Automated alerts to security teams when critical/high vulnerabilities are discovered
- **Configurable Thresholds**: Set custom severity levels for different notification channels
- **Distribution Lists**: Support for multiple stakeholder groups (dev teams, security, management)
- **Rich HTML Emails**: Professional email reports with charts and detailed vulnerability information

### 📊 **Executive Reporting**
- **Security Dashboards**: Real-time vulnerability metrics and trends
- **Compliance Reports**: Generate reports for SOX, PCI-DSS, HIPAA compliance requirements
- **Risk Assessment**: Prioritize vulnerabilities based on exploitability and business impact
- **PDF Executive Summaries**: Board-ready security status reports

## 🚀 Quick Start

### Prerequisites
- **Java**: JDK 8 or higher
- **Maven**: 3.6.0 or higher  
- **Memory**: 1GB+ RAM for large enterprise projects

### Basic Installation

Add the plugin to your `pom.xml`:

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
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
# Community Edition - Free vulnerability scanning
mvn io.github.dodogeny:bastion-maven-community-plugin:1.0.0:scan
```

Reports will be generated in `target/security/` directory.

**Community Features Included:**
- OWASP Dependency-Check vulnerability scanning
- HTML, JSON, and CSV reports with graphical dependency trees
- Historical trend analysis and performance metrics
- In-memory database or JSON file storage options
- Multi-module project support

## 🛠️ Community Edition Usage Guide

### Available Maven Goals

Bastion Community provides this Maven goal for vulnerability management:

| Goal | Description | Community Edition |
|------|-------------|------------------|
| `scan` | Run complete vulnerability scan with integrated trend analysis | ✅ Full support |

> **📊 Trend Analysis:** Historical trend analysis is built into the `scan` goal when using JSON file storage. No separate `trend-analysis` goal needed!

### Basic Usage Examples

#### 1. Simple Vulnerability Scan

```bash
# Basic scan with default settings
mvn io.github.dodogeny:bastion-maven-community-plugin:1.0.0:scan

# Or if plugin is configured in pom.xml
mvn bastion:scan
```

#### 2. With NVD API Key (Recommended)

```bash
# Using NVD API key for faster, more reliable scans
mvn bastion:scan -Dbastion.nvd.apiKey=YOUR_NVD_API_KEY

# Using environment variable
export NVD_API_KEY="your-nvd-api-key"
mvn bastion:scan -Dbastion.nvd.apiKey=${NVD_API_KEY}
```

#### 3. Storage Mode Options

```bash
# In-memory database (default - fastest)
mvn bastion:scan -Dbastion.community.storageMode=IN_MEMORY

# JSON file storage (persistent, with trend analysis)
mvn bastion:scan -Dbastion.community.storageMode=JSON_FILE

# Custom JSON file location
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.storage.jsonFilePath=/path/to/custom-vulnerabilities.json
```

#### 4. Report Generation

```bash
# Generate all available reports (HTML, JSON, CSV)
mvn bastion:scan

# Specific report format focus
mvn bastion:scan -Dbastion.reporting.formats.html=true
mvn bastion:scan -Dbastion.reporting.formats.json=true
mvn bastion:scan -Dbastion.reporting.formats.csv=true
```

#### 5. Historical Trend Analysis

```bash
# Enable trend analysis with JSON storage (first scan)
mvn bastion:scan -Dbastion.community.storageMode=JSON_FILE

# Subsequent scans automatically generate trend analysis
mvn bastion:scan -Dbastion.community.storageMode=JSON_FILE

# Custom JSON file location for trend tracking
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.storage.jsonFilePath=/path/to/trend-data.json
```

> **📈 How Trend Analysis Works:** Trend analysis is automatically generated when using JSON file storage and you have at least 2 historical scans. The scan goal creates both regular reports AND a dedicated trend report (`bastion-trend-report-{project}.html`).

#### 6. Multi-Module Projects

```bash
# Scan multi-module project from parent directory
mvn bastion:scan -Dbastion.multiModule.enabled=true

# With parallel scanning for faster results
mvn bastion:scan \
  -Dbastion.multiModule.enabled=true \
  -Dbastion.multiModule.parallelScanning=true \
  -Dbastion.multiModule.threadCount=4
```

#### 7. Performance Options

```bash
# Enhanced scanning with timeout configuration
mvn bastion:scan -Dbastion.scanner.timeout=300000

# Multi-module scanning enabled
mvn bastion:scan -Dbastion.enableMultiModule=true
```

#### 8. Data Management

```bash
# Purge data before scan (JSON file mode)
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true

# Purge with confirmation
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.force=true

# Dry run - preview what would be purged
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.dryRun=true
```

#### 9. Build Integration

```bash
# Control build failure behavior
mvn bastion:scan -Dbastion.failOnError=true

# Set severity threshold for build failures
mvn bastion:scan -Dbastion.severityThreshold=CRITICAL
mvn bastion:scan -Dbastion.severityThreshold=HIGH
mvn bastion:scan -Dbastion.severityThreshold=MEDIUM

# Skip scan entirely
mvn bastion:scan -Dbastion.skip=true
```

#### 10. Advanced Configuration Options

```bash
# Custom output directory
mvn bastion:scan -Dbastion.outputDirectory=${project.build.directory}/custom-reports

# Specify report formats
mvn bastion:scan -Dbastion.reportFormats=HTML,JSON

# Database connection (if available)
mvn bastion:scan \
  -Dbastion.database.url=jdbc:h2:~/bastion-db \
  -Dbastion.database.username=bastion \
  -Dbastion.database.password=secure

# Scanner timeout (milliseconds)
mvn bastion:scan -Dbastion.scanner.timeout=600000  # 10 minutes
```

### 📋 POM Configuration Examples

#### Basic Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Basic settings -->
        <skip>false</skip>
        <failOnError>true</failOnError>
        <severityThreshold>MEDIUM</severityThreshold>
        <reportFormats>HTML,JSON</reportFormats>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>scan</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

#### JSON File Storage Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- JSON storage configuration -->
        <communityStorageMode>JSON_FILE</communityStorageMode>
        <jsonFilePath>${project.build.directory}/security/bastion-vulnerabilities.json</jsonFilePath>
        
        <!-- Alternative: use explicit JSON file storage -->
        <useJsonFileStorage>true</useJsonFileStorage>
        
        <!-- Output settings -->
        <outputDirectory>${project.build.directory}/bastion-reports</outputDirectory>
        <reportFormats>HTML,JSON</reportFormats>
    </configuration>
</plugin>
```

#### Multi-Module Project Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Multi-module settings -->
        <enableMultiModule>true</enableMultiModule>
        
        <!-- Storage for trend analysis -->
        <communityStorageMode>JSON_FILE</communityStorageMode>
        <jsonFilePath>${project.build.directory}/security/multi-module-vulnerabilities.json</jsonFilePath>
        
        <!-- Scanner configuration -->
        <scannerTimeout>600000</scannerTimeout> <!-- 10 minutes -->
        <severityThreshold>HIGH</severityThreshold>
        
        <!-- Output settings -->
        <reportFormats>HTML,JSON</reportFormats>
        <outputDirectory>${project.build.directory}/bastion-reports</outputDirectory>
    </configuration>
</plugin>
```

#### Build Failure Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Build failure policies -->
        <failOnError>true</failOnError>
        <severityThreshold>CRITICAL</severityThreshold> <!-- CRITICAL, HIGH, MEDIUM -->
        
        <!-- Scanner settings -->
        <scannerTimeout>300000</scannerTimeout> <!-- 5 minutes -->
        
        <!-- Database configuration -->
        <databaseUrl>jdbc:h2:${project.build.directory}/bastion-db/vulnerabilities</databaseUrl>
        <databaseUsername>bastion</databaseUsername>
        <databasePassword>secure</databasePassword>
    </configuration>
    <executions>
        <execution>
            <phase>verify</phase>
            <goals>
                <goal>scan</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

#### Advanced Configuration with All Options

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- NVD API configuration -->
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
        
        <!-- Storage configuration -->
        <communityStorageMode>JSON_FILE</communityStorageMode>
        <jsonFilePath>${user.home}/.m2/bastion-cache/${project.artifactId}-vulnerabilities.json</jsonFilePath>
        
        <!-- Alternative storage method -->
        <!-- <useJsonFileStorage>true</useJsonFileStorage> -->
        
        <!-- Purge settings -->
        <purgeBeforeScan>false</purgeBeforeScan>
        <force>false</force>
        <confirmPurge>false</confirmPurge>
        <projectOnly>true</projectOnly>
        <olderThanDays>30</olderThanDays>
        <dryRun>false</dryRun>
        
        <!-- Multi-module support -->
        <enableMultiModule>true</enableMultiModule>
        
        <!-- Scanner configuration -->
        <scannerTimeout>600000</scannerTimeout> <!-- 10 minutes -->
        <severityThreshold>HIGH</severityThreshold>
        
        <!-- Build control -->
        <skip>false</skip>
        <failOnError>true</failOnError>
        
        <!-- Output configuration -->
        <outputDirectory>${project.build.directory}/bastion-reports</outputDirectory>
        <reportFormats>HTML,JSON</reportFormats>
        
        <!-- Database configuration (if not using JSON) -->
        <databaseUrl>jdbc:h2:${project.build.directory}/bastion-db/vulnerabilities</databaseUrl>
        <databaseUsername>bastion</databaseUsername>
        <databasePassword>${env.DB_PASSWORD}</databasePassword>
    </configuration>
</plugin>
```

### 🔑 NVD API Key Setup (Recommended)

The National Vulnerability Database (NVD) API key significantly improves scanning performance and reliability.

#### Get Your Free NVD API Key

1. **Visit NVD Developer Portal**
   ```bash
   https://nvd.nist.gov/developers/request-an-api-key
   ```

2. **Register for Free Account**
   - Complete the registration form
   - Verify your email address
   - Request API key (instant approval)

#### Configure NVD API Key

**Option 1: Environment Variable (Recommended)**
```bash
# Add to ~/.bashrc or ~/.zshrc
export NVD_API_KEY="your-nvd-api-key-here"

# Or set for current session
export NVD_API_KEY="your-nvd-api-key-here"
mvn bastion:scan -Dbastion.nvd.apiKey=${NVD_API_KEY}
```

**Option 2: Maven Settings**
```xml
<!-- ~/.m2/settings.xml -->
<settings>
    <profiles>
        <profile>
            <id>bastion-community</id>
            <properties>
                <nvd.api.key>your-nvd-api-key-here</nvd.api.key>
            </properties>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>bastion-community</activeProfile>
    </activeProfiles>
</settings>
```

**Option 3: Project POM**
```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.0.0</version>
    <configuration>
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
        <!-- or from Maven properties -->
        <nvdApiKey>${nvd.api.key}</nvdApiKey>
    </configuration>
</plugin>
```

**Benefits of NVD API Key:**
- 📈 **5x Faster Scans**: Higher rate limits (2000 requests/30s vs 50/30s)
- 🔄 **More Reliable**: Reduced chance of rate limiting
- 📊 **Latest Data**: Access to most current vulnerability information
- 🚀 **Better Performance**: Priority processing from NVD servers

### 💾 Storage Configuration Options

#### In-Memory Database (Default)

**Best for:** Quick scans, CI/CD pipelines, temporary analysis

```xml
<configuration>
    <communityStorageMode>IN_MEMORY</communityStorageMode>
</configuration>
```

**Command Line:**
```bash
mvn bastion:scan -Dbastion.community.storageMode=IN_MEMORY
```

**Features:**
- ⚡ **Zero Setup**: No files created
- 🚀 **Fastest Performance**: All data in memory
- 🧹 **Auto Cleanup**: Data cleared when Maven session ends
- ❌ **No Persistence**: No historical trend analysis

#### JSON File Storage

**Best for:** Historical tracking, trend analysis, audit trails

```xml
<configuration>
    <communityStorageMode>JSON_FILE</communityStorageMode>
    <jsonFilePath>${project.build.directory}/security/bastion-vulnerabilities.json</jsonFilePath>
</configuration>
```

**Command Line:**
```bash
# Default JSON location
mvn bastion:scan -Dbastion.community.storageMode=JSON_FILE

# Custom location
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.storage.jsonFilePath=/path/to/custom.json
```

**Features:**
- 📄 **Persistent Storage**: Data survives between scans
- 📈 **Full Trend Analysis**: Historical vulnerability tracking
- 🔍 **Version Control**: JSON files can be committed
- 👁️ **Human Readable**: Easy to inspect and analyze manually

**Recommended JSON File Locations:**

```xml
<!-- Per-project storage (recommended) -->
<jsonFilePath>${project.build.directory}/security/${project.artifactId}-vulnerabilities.json</jsonFilePath>

<!-- Global storage across projects -->
<jsonFilePath>${user.home}/.m2/bastion-cache/global-vulnerabilities.json</jsonFilePath>

<!-- Team shared storage -->
<jsonFilePath>${project.basedir}/.bastion/vulnerabilities.json</jsonFilePath>

<!-- CI/CD friendly -->
<jsonFilePath>${env.WORKSPACE}/security-reports/${project.artifactId}-vulnerabilities.json</jsonFilePath>
```

### 🗑️ Data Purge Options

#### Purge Commands

```bash
# Preview what would be purged (safe)
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.dryRun=true

# Purge with confirmation prompt
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true

# Force purge (no confirmation)
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.force=true

# Purge only current project data
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.projectOnly=true

# Purge data older than 30 days
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.olderThanDays=30
```

#### POM Purge Configuration

```xml
<configuration>
    <communityStorageMode>JSON_FILE</communityStorageMode>
    <purgeBeforeScan>true</purgeBeforeScan>
    <purge>
        <force>false</force>              <!-- Ask for confirmation -->
        <projectOnly>true</projectOnly>   <!-- Only current project -->
        <olderThanDays>0</olderThanDays>  <!-- All records (0 = no age limit) -->
        <dryRun>false</dryRun>           <!-- Execute the purge -->
    </purge>
</configuration>
```

### 📊 Scan Statistics Output

Bastion provides comprehensive scan statistics and performance metrics:

```
📊 Bastion Scan Statistics & Performance Metrics
📦 JARs Scanned: 127
🔍 CVEs Found: 23 (8 unique)
🎯 CVEs with Exploits: 5
📈 Average CVSS Score: 6.7
🚨 Most Vulnerable: com.fasterxml.jackson.core:jackson-core:2.9.8

⏱️ Performance Breakdown:
├─ Initialization: 1.2s
├─ Dependency Resolution: 3.4s  
├─ Vulnerability Analysis: 12.8s
├─ Report Generation: 2.1s
└─ Total Duration: 19.5s

💾 Resource Usage:
├─ Peak Memory: 384 MB
├─ Processing Speed: 6.5 JARs/second
├─ Cache Performance: 78% hit rate (234/300 queries)
└─ Slowest Phase: Vulnerability Analysis
```

## 🚀 Upgrade to Enterprise Edition

> **✅ Enterprise Edition Now Available**: The Bastion Maven Plugin Enterprise Edition is now available on Maven Central with advanced security features, IP-protected implementation, and enterprise licensing through LemonSqueezy.

Ready to unlock advanced security features? **Bastion Enterprise** provides everything in the Community Edition plus powerful enterprise-grade capabilities.

### 🆚 Community vs Enterprise Comparison

| Feature | Community Edition | Enterprise Edition |
|---------|------------------|-------------------|
| **Core Scanning** | ✅ OWASP Dependency-Check | ✅ Enhanced with additional sources |
| **Report Formats** | ✅ HTML, JSON, CSV | ✅ + PDF, SARIF |
| **Storage Options** | ✅ In-memory, JSON file | ✅ + PostgreSQL, MySQL, H2 |
| **Trend Analysis** | ✅ Basic historical tracking | ✅ Advanced multi-project analytics |
| **Performance** | ✅ Basic metrics | ✅ Detailed performance profiling |
| **Email Alerts** | ❌ | ✅ Automated security notifications |
| **Multi-Database** | ❌ | ✅ Enterprise database support |
| **GitHub Integration** | ✅ Basic | ✅ Enhanced API access |
| **Support** | ❌ Community support | ✅ Priority enterprise support |
| **Licensing** | ✅ Free & Open Source | 💰 Commercial license required |

### 🛒 How to Upgrade

> **🎉 Enterprise Edition Available Now**: The Enterprise Edition is now available on Maven Central with IP-protected implementation and enterprise licensing through LemonSqueezy.

#### Step 1: Purchase Enterprise License

Visit our LemonSqueezy store to purchase your enterprise license:

```bash
# Available at:
https://bastionplugin.lemonsqueezy.com
```

**Current Plans:**
- **Monthly Subscription**: $29/month per team
- **Annual Subscription**: $290/year per team (17% savings)

#### Step 2: Update Your Project Configuration

Replace the Community Edition plugin with Enterprise Edition:

```xml
<!-- Remove Community Edition -->
<!-- 
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.0.0</version>
</plugin>
-->

<!-- Add Enterprise Edition -->
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Enable Enterprise features -->
        <apiKey>${env.BASTION_API_KEY}</apiKey>
        <licenseProvider>lemonsqueezy</licenseProvider>
        
        <!-- Enterprise database configuration -->
        <database>
            <type>postgresql</type>
            <url>jdbc:postgresql://localhost:5432/bastion_security</url>
            <username>${env.DB_USER}</username>
            <password>${env.DB_PASSWORD}</password>
        </database>
        
        <!-- Email notifications -->
        <notifications>
            <enabled>true</enabled>
            <smtp>
                <host>smtp.company.com</host>
                <port>587</port>
                <username>${env.SMTP_USER}</username>
                <password>${env.SMTP_PASS}</password>
                <useStartTLS>true</useStartTLS>
            </smtp>
            <recipients>
                <securityTeam>security@company.com</securityTeam>
                <developmentTeam>dev-team@company.com</developmentTeam>
            </recipients>
        </notifications>
    </configuration>
</plugin>
```

#### Step 3: Configure Environment Variables

Set up your enterprise license and database credentials:

```bash
# LemonSqueezy license key (from purchase email)
export BASTION_API_KEY="bsk_live_abc123..."

# Database credentials
export DB_USER="bastion_user"
export DB_PASSWORD="secure_password"

# Email notification credentials
export SMTP_USER="security-scanner@company.com"
export SMTP_PASS="app_specific_password"
```

### 🔒 Intellectual Property Protection

The Enterprise Edition includes IP-protected implementation to safeguard proprietary code while maintaining full compatibility:

#### Available Artifact Variants

| Artifact Type | Classifier | Description |
|---------------|------------|-------------|
| **Standard JAR** | _(none)_ | Standard compiled classes for Maven Central compliance |
| **Protected JAR** | `protected` | IP-protected implementation with code obfuscation |

#### Installation Options

**Option 1: Standard Artifact (Default)**
```xml
<dependency>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-enterprise-features</artifactId>
    <version>1.0.0</version>
</dependency>
```

**Option 2: Protected Artifact (Recommended for Production)**
```xml
<dependency>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-enterprise-features</artifactId>
    <version>1.0.0</version>
    <classifier>protected</classifier>
</dependency>
```

> **🛡️ Protection Features**: The protected artifact includes Maven Shade Plugin-based obfuscation that protects implementation details while preserving public API compatibility for seamless integration with community edition and third-party tools.

#### Step 4: Verify Enterprise Activation

Run a scan to verify your enterprise license:

```bash
mvn io.github.dodogeny:bastion-maven-plugin-enterprise:1.0.0:scan
```

Look for the success message:
```
✅ LemonSqueezy license validated successfully
💼 Bastion Enterprise Edition activated
🚀 All premium features unlocked
```

### 🗄️ Setting Up Enterprise Database

#### PostgreSQL Setup (Recommended)

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE bastion_security;
CREATE USER bastion_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE bastion_security TO bastion_user;
\q

# Configure environment
export DB_USER="bastion_user"
export DB_PASSWORD="secure_password"
```

#### Alternative: H2 File Database (Simpler Setup)

```xml
<database>
    <type>h2</type>
    <path>${user.home}/.m2/bastion-security-cache/vulnerability-db</path>
    <username>bastion</username>
    <password>${env.DB_PASSWORD}</password>
</database>
```

### 📧 Configure Email Notifications

Enterprise Edition includes intelligent email alerts:

```xml
<notifications>
    <enabled>true</enabled>
    <smtp>
        <host>smtp.company.com</host>
        <port>587</port>
        <username>${env.SMTP_USER}</username>
        <password>${env.SMTP_PASS}</password>
        <useStartTLS>true</useStartTLS>
    </smtp>
    
    <!-- Alert thresholds -->
    <alertOn>
        <critical>true</critical>       <!-- Always alert on critical -->
        <high>true</high>              <!-- Alert on high severity -->
        <vulnerabilityCount>5</vulnerabilityCount>  <!-- Alert if >5 total -->
    </alertOn>
    
    <!-- Distribution lists -->
    <recipients>
        <securityTeam>security@company.com,ciso@company.com</securityTeam>
        <developmentTeam>dev-leads@company.com</developmentTeam>
        <management>vp-engineering@company.com</management>
    </recipients>
</notifications>
```

### 🆘 Enterprise Support

> **🎯 Enterprise Support**: Dedicated enterprise support services will be available with the Enterprise Edition release.

Enterprise customers will get priority support:

- **Email Support**: enterprise-support@dodogeny.mu (when available)
- **Response Time**: 24 hours for critical issues
- **Dedicated Slack Channel**: Available for annual subscribers
- **Migration Assistance**: Help migrating from Community to Enterprise

### 📊 Enterprise Reporting Features

> **📊 Enterprise Reporting**: These advanced reporting capabilities will be included in the upcoming Enterprise Edition.

Planned advanced reporting capabilities:

- **PDF Reports**: Executive-ready security summaries
- **SARIF Output**: Integration with security tools and IDEs
- **Multi-Project Analytics**: Cross-project vulnerability tracking  
- **Compliance Reports**: SOX, PCI-DSS, HIPAA compliance templates
- **Real-time Dashboards**: Live security metrics

### 🔄 Migration Process

Upgrading from Community to Enterprise is seamless:

1. **Data Migration**: Existing JSON files automatically imported
2. **Configuration**: Minimal changes to existing setup
3. **Zero Downtime**: No disruption to existing workflows
4. **Backward Compatible**: All Community features preserved

## 🔐 Enterprise Licensing

### Open Source vs Commercial Edition

Bastion offers both community and commercial editions:

**Community Edition** (Free):
- OWASP Dependency-Check scanner with NVD API key support
- HTML, JSON, CSV reports with graphical dependency trees
- Dedicated trend analysis report with historical tracking
- Configurable storage (in-memory database or JSON file)
- Basic performance metrics
- Multi-module scanning support

**Commercial Edition** (Licensed through LemonSqueezy):
- All Community Edition features plus:
- **Persistent H2/PostgreSQL/MySQL databases**
- **Enhanced historical trend analysis** across projects
- **PDF and SARIF report generation**
- **Advanced email notifications**
- **Enhanced GitHub Security Advisory integration** 
- **Real-time monitoring capabilities**
- **Enterprise support and priority assistance**

### LemonSqueezy Licensing (Commercial Edition Only)

**Important**: All commercial licenses are exclusively managed through LemonSqueezy. No other licensing methods are supported.

#### Step 1: Purchase Commercial License

1. **Visit LemonSqueezy Store**
   ```bash
   # Open in your browser
   https://bastionplugin.lemonsqueezy.com
   ```

2. **Select Your Plan**
   - **Monthly**: Monthly Subscription License

3. **Complete Payment**
   - Secure checkout via LemonSqueezy
   - Supports credit cards, PayPal, and international payment methods
   - Instant license delivery via email

#### Step 2: Configure API Key

After purchase, you'll receive your LemonSqueezy API key:

1. **Set Environment Variable** (Recommended)
   ```bash
   export BASTION_API_KEY="bsk_live_abc123..."
   ```

2. **Configure in Maven Settings**
   Add to `~/.m2/settings.xml`:
   ```xml
   <settings>
     <profiles>
       <profile>
         <id>bastion-commercial</id>
         <properties>
           <bastion.apiKey>${env.BASTION_API_KEY}</bastion.apiKey>
         </properties>
       </profile>
     </profiles>
     <activeProfiles>
       <activeProfile>bastion-commercial</activeProfile>
     </activeProfiles>
   </settings>
   ```

3. **Project-Level Configuration**
   Add to your project's `pom.xml`:
   ```xml
   <plugin>
     <groupId>io.github.dodogeny</groupId>
     <artifactId>bastion-maven-plugin-enterprise</artifactId>
     <version>1.0.0</version>
     <configuration>
       <apiKey>${bastion.apiKey}</apiKey>
       <!-- LemonSqueezy license validation -->
       <licenseProvider>lemonsqueezy</licenseProvider>
     </configuration>
   </plugin>
   ```

#### Step 3: Verify License Activation

Run a scan to verify your commercial license:

```bash
# Using environment variable

# Using command-line parameter
mvn bastion:scan -Dbastion.apiKey=bsk_live_abc123...
```

Look for the success message:
```
✅ LemonSqueezy license validated successfully
💼 Bastion Commercial Edition activated
🚀 All premium features unlocked
```

##### NVD API Key Configuration (Optional but Recommended)

The National Vulnerability Database (NVD) provides faster and more reliable vulnerability data when using an API key:

1. **Get Your Free NVD API Key**
   - Visit: https://nvd.nist.gov/developers/request-an-api-key
   - Register for a free account
   - Request an API key

2. **Configure the API Key**
   ```bash
   # Environment variable (recommended)
   export NVD_API_KEY="your-nvd-api-key-here"
   
   # Command line parameter
   mvn bastion:scan -Dbastion.nvd.apiKey=your-nvd-api-key-here
   ```

3. **Maven Configuration**
   ```xml
   <plugin>
     <groupId>io.github.dodogeny</groupId>
     <artifactId>bastion-maven-plugin-enterprise</artifactId>
     <version>1.0.0</version>
     <configuration>
       <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
     </configuration>
   </plugin>
   ```

**Benefits of NVD API Key:**
- 📈 **Faster scans**: Higher rate limits for vulnerability database updates
- 🔄 **More reliable**: Reduced chance of rate limiting during scans
- 📊 **Better data**: Access to the latest vulnerability information

### Security Best Practices

- **Never commit API keys** to version control
- Store API keys in environment variables or secure vaults
- Use Maven settings encryption for additional security:
  ```bash
  mvn --encrypt-master-password
  mvn --encrypt-password bsk_live_abc123...
  ```

## 💾 Storage Configuration

### Community Edition Storage Options

The Community Edition offers two storage modes to choose from:

#### Option 1: In-Memory Database (Default)

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Community Edition (default) -->
        
        <!-- Storage mode selection -->
        <communityStorageMode>IN_MEMORY</communityStorageMode>
    </configuration>
</plugin>
```

**Command Line Usage:**
```bash
# Use in-memory database (default)
mvn bastion:scan -Dbastion.community.storageMode=IN_MEMORY
```

**Features:**
- ⚡ **Zero Setup**: No database installation required
- 🗄️ **Session Storage**: Data persists during Maven session
- 📊 **Basic Trends**: Limited trend analysis capabilities
- 🧹 **Memory Management**: Automatic cleanup when Maven session ends

#### Option 2: JSON File Storage

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Community Edition -->
        
        <!-- Storage mode selection -->
        <communityStorageMode>JSON_FILE</communityStorageMode>
        <jsonFilePath>${project.build.directory}/bastion-vulnerabilities.json</jsonFilePath>
    </configuration>
</plugin>
```

**Command Line Usage:**
```bash
# Use JSON file storage
mvn bastion:scan -Dbastion.community.storageMode=JSON_FILE

# Custom JSON file location
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.storage.jsonFilePath=/custom/path/vulnerabilities.json
```

**Features:**
- 📄 **File Persistence**: Data survives between scans and reboots
- 📈 **Full Trend Analysis**: Complete historical trend tracking
- 🔍 **Version Control**: JSON files can be committed for audit trails
- 🛠️ **Manual Analysis**: Human-readable format for direct inspection
- 🧹 **Purge Support**: Selective data cleanup capabilities

### Commercial Edition - Persistent Databases

#### H2 Database (File-based)

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <apiKey>${env.BASTION_API_KEY}</apiKey>
        
        <!-- H2 Database Configuration -->
        <database>
            <type>h2</type>
            <path>${user.home}/.m2/bastion-security-cache/vulnerability-db</path>
            <username>bastion</username>
            <password>${env.DB_PASSWORD}</password>
        </database>
    </configuration>
</plugin>
```

#### PostgreSQL Database

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <apiKey>${env.BASTION_API_KEY}</apiKey>
        
        <!-- PostgreSQL Configuration -->
        <database>
            <type>postgresql</type>
            <url>jdbc:postgresql://localhost:5432/bastion_security</url>
            <username>${env.DB_USER}</username>
            <password>${env.DB_PASSWORD}</password>
            <connectionPoolSize>10</connectionPoolSize>
            
            <!-- Flyway Migration Settings -->
            <flyway>
                <locations>classpath:db/migration</locations>
                <validateOnMigrate>true</validateOnMigrate>
                <baselineOnMigrate>true</baselineOnMigrate>
            </flyway>
        </database>
    </configuration>
</plugin>
```

#### MySQL Database

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <apiKey>${env.BASTION_API_KEY}</apiKey>
        
        <!-- MySQL Configuration -->
        <database>
            <type>mysql</type>
            <url>jdbc:mysql://localhost:3306/bastion_security_db</url>
            <username>${env.DB_USER}</username>
            <password>${env.DB_PASSWORD}</password>
            <connectionPoolSize>15</connectionPoolSize>
        </database>
    </configuration>
</plugin>
```

### Database Setup Steps

#### 1. PostgreSQL Setup

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE bastion_security;
CREATE USER bastion_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE bastion_security TO bastion_user;
\q

# Set environment variables
export DB_USER="bastion_user"
export DB_PASSWORD="secure_password"
```

#### 2. MySQL Setup

```bash
# Install MySQL
sudo apt-get install mysql-server

# Create database and user
mysql -u root -p
CREATE DATABASE bastion_security_db;
CREATE USER 'bastion_user'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON bastion_security_db.* TO 'bastion_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Set environment variables
export DB_USER="bastion_user"
export DB_PASSWORD="secure_password"
```

#### 3. H2 Database (File-based)

```bash
# Create directory for H2 database
mkdir -p ~/.m2/bastion-security-cache

# Set database password
export DB_PASSWORD="your_secure_h2_password"

# H2 will be automatically created on first run
```

### Database Migration Management

Bastion uses Flyway for database schema management:

```xml
<configuration>
    <database>
        <flyway>
            <!-- Migration script locations -->
            <locations>classpath:db/migration</locations>
            
            <!-- Validation settings -->
            <validateOnMigrate>true</validateOnMigrate>
            <baselineOnMigrate>true</baselineOnMigrate>
            <cleanOnValidationError>false</cleanOnValidationError>
            
            <!-- Advanced settings -->
            <outOfOrder>false</outOfOrder>
            <ignoreMissingMigrations>false</ignoreMissingMigrations>
            <repairOnMigrate>false</repairOnMigrate>
        </flyway>
    </database>
</configuration>
```

### Database Performance Tuning

For enterprise deployments with large codebases:

```xml
<configuration>
    <database>
        <!-- Connection pool settings -->
        <connectionPoolSize>20</connectionPoolSize>
        <connectionTimeout>30000</connectionTimeout>
        <idleTimeout>600000</idleTimeout>
        <maxLifetime>1800000</maxLifetime>
        
        <!-- Performance optimizations -->
        <performance>
            <batchSize>1000</batchSize>
            <enableStatistics>true</enableStatistics>
            <enableQueryCache>true</enableQueryCache>
            <queryTimeout>300000</queryTimeout>
        </performance>
        
        <!-- Indexing strategy -->
        <indexing>
            <createOnStartup>true</createOnStartup>
            <rebuildPeriodDays>7</rebuildPeriodDays>
        </indexing>
    </database>
</configuration>
```

### License Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- LemonSqueezy License Configuration -->
        <apiKey>${env.BASTION_API_KEY}</apiKey>
        <licenseProvider>lemonsqueezy</licenseProvider>
        
        <!-- LemonSqueezy Settings -->
        <lemonsqueezy>
            <storeId>your-store-id</storeId>
            <validateOnline>true</validateOnline>
            <cacheValidation>true</cacheValidation>
            <cacheDurationHours>24</cacheDurationHours>
        </lemonsqueezy>
    </configuration>
</plugin>
```

### LemonSqueezy License Security

Bastion's LemonSqueezy integration provides enterprise-grade security:
- **API Key Authentication**: Secure token-based validation
- **Real-time Verification**: License status checked against LemonSqueezy API
- **Fraud Protection**: Built-in LemonSqueezy fraud detection
- **Subscription Management**: Automatic renewal and cancellation handling
- **Usage Analytics**: Track license usage across your organization

## 📧 Email Notifications Setup

Configure email alerts for your security team (Commercial Edition):

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Email Configuration -->
        <notifications>
            <enabled>true</enabled>
            <smtp>
                <host>smtp.company.com</host>
                <port>587</port>
                <username>${env.SMTP_USER}</username>
                <password>${env.SMTP_PASS}</password>
                <useStartTLS>true</useStartTLS>
            </smtp>
            
            <!-- Distribution Lists -->
            <recipients>
                <securityTeam>security@company.com,ciso@company.com</securityTeam>
                <developmentTeam>dev-leads@company.com</developmentTeam>
                <management>vp-engineering@company.com</management>
            </recipients>
            
            <!-- Alert Thresholds -->
            <alertOn>
                <critical>true</critical>       <!-- Always alert on critical -->
                <high>true</high>              <!-- Alert on high severity -->
                <medium>false</medium>         <!-- No alerts for medium -->
                <vulnerabilityCount>5</vulnerabilityCount>  <!-- Alert if >5 total -->
            </alertOn>
            
            <!-- Email Templates -->
            <templates>
                <criticalAlert>critical-vuln-template.ftl</criticalAlert>
                <dailySummary>daily-security-summary.ftl</dailySummary>
                <weeklyReport>weekly-security-report.ftl</weeklyReport>
            </templates>
            
            <!-- Enterprise Features -->
            <realTimeAlerts>true</realTimeAlerts>
        </notifications>
    </configuration>
</plugin>
```

### Environment Variables for Email

```bash
# SMTP Configuration
export SMTP_USER="security-scanner@company.com"
export SMTP_PASS="secure_app_password"

# Optional: Custom email settings
export BASTION_FROM_EMAIL="Bastion Scanner <noreply@company.com>"
export BASTION_REPLY_TO="security-team@company.com"


## 🌐 API-Based Licensing

```bash
# LemonSqueezy API Configuration
export BASTION_API_KEY="bsk_live_abc123..." # Your LemonSqueezy license key
export BASTION_STORE_ID="12345"              # Your LemonSqueezy store ID
```

### LemonSqueezy License Troubleshooting

**License validation failed:**
```
❌ LemonSqueezy license validation failed
```
**Solutions:**
1. Verify your API key is correct
2. Check internet connection for license validation
3. Ensure subscription is active in LemonSqueezy dashboard
4. Contact support if issues persist

**Subscription expired:**
```
⚠️ LemonSqueezy subscription expired
```
**Solution:** Renew your subscription at https://bastion.lemonsqueezy.com

**API rate limits:**
```
⏰ LemonSqueezy API rate limit reached
```
**Solution:** License validation is cached for 24 hours to minimize API calls

## 🏗️ Enterprise Configuration

### Multi-Module Projects

For large enterprise applications with multiple modules:

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Multi-module optimization -->
        <multiModule>
            <enabled>true</enabled>
            <aggregateReports>true</aggregateReports>
            <parallelScanning>true</parallelScanning>
            <threadCount>4</threadCount>
        </multiModule>
        
        <!-- Performance tuning -->
        <performance>
            <batchSize>100</batchSize>
            <cacheEnabled>true</cacheEnabled>
            <cacheDurationHours>24</cacheDurationHours>
        </performance>
        
        <!-- Enterprise database -->
        <database>
            <type>postgresql</type>
            <url>jdbc:postgresql://db-server:5432/bastion</url>
            <username>${env.DB_USER}</username>
            <password>${env.DB_PASS}</password>
            <connectionPoolSize>10</connectionPoolSize>
            <flyway>
                <locations>classpath:db/migration</locations>
                <validateOnMigrate>true</validateOnMigrate>
            </flyway>
        </database>
        
        <!-- Statistics and Performance Monitoring -->
        <statistics>
            <enabled>true</enabled>
            <includePerformanceMetrics>true</includePerformanceMetrics>
            <trackResourceUsage>true</trackResourceUsage>
            <identifyBottlenecks>true</identifyBottlenecks>
        </statistics>
    </configuration>
</plugin>
```

### Security Policies & Compliance

Define organizational security policies:

```xml
<configuration>
    <securityPolicies>
        <!-- Fail build policies -->
        <failOnCritical>true</failOnCritical>
        <failOnHigh>true</failOnHigh>
        <maxAllowedVulnerabilities>0</maxAllowedVulnerabilities>
        
        <!-- Grace periods for known issues -->
        <gracePeriods>
            <critical>0</critical>     <!-- No grace period for critical -->
            <high>7</high>             <!-- 7 days for high severity -->
            <medium>30</medium>        <!-- 30 days for medium -->
        </gracePeriods>
        
        <!-- Compliance frameworks -->
        <compliance>
            <framework>PCI-DSS</framework>
            <generateComplianceReport>true</generateComplianceReport>
        </compliance>
    </securityPolicies>
</configuration>
```

## 🔍 Vulnerability Data Sources

Bastion supports multiple vulnerability intelligence sources:

### Open Source Edition (Free)
- **OWASP Dependency-Check**: Comprehensive open-source vulnerability database
- **NVD (National Vulnerability Database)**: Official US government CVE database
- **Basic GitHub Integration**: Public vulnerability advisories

### Commercial Edition (Enterprise)
- **All Community Sources**: Plus enhanced capabilities
- **Enhanced GitHub Integration**: Commercial API access with enhanced metadata
- **Extended Intelligence**: Integration with additional vulnerability sources

```xml
<configuration>
    <!-- Scanner Configuration -->
    <scanners>
        <scanner>owasp</scanner>           <!-- Always enabled (community) -->
        <scanner>github</scanner>          <!-- GitHub Security Advisory -->
    </scanners>
    
    <!-- API Keys (Commercial Edition) -->
    <apiKeys>
        <github>${env.GITHUB_TOKEN}</github>
    </apiKeys>
</configuration>
```

## 📊 Reports & Analytics

### Enhanced Trend Analysis (v1.0.0+)

Bastion now features advanced trend analysis capabilities with interactive visualizations:

#### 🚀 **New Features in v1.0.0**

##### 📈 **Historical Trend Charts**
- **Interactive Timeline**: Visual representation of vulnerable JARs and CVEs over time
- **Multi-Metric Tracking**: Simultaneously track vulnerable JARs, total CVEs, and critical CVEs
- **Smart Baseline Detection**: First scan establishes baseline for future trend comparisons
- **Responsive Design**: Charts adapt to different screen sizes and data ranges

```
📊 JARs and CVEs Over Time
┌────────────────────────────────────────────────────────────┐
│ 100 ┤                                                        │
│  80 ┤     ●━━━●━━━●  Vulnerable JARs                         │
│  60 ┤       ○───○───○  Total CVEs                           │
│  40 ┤         ◆───◆───◆  Critical CVEs                      │
│   0 └────────────────────────────────────────────────────── │
│     2 scans ago    Previous    Current                      │
└────────────────────────────────────────────────────────────┘
```

##### 🎯 **Smart Conditional Display**
- **Context-Aware Sections**: JAR distribution charts only appear when CVEs are detected
- **Clean UI**: No clutter when all dependencies are secure
- **Enhanced User Experience**: Focus on relevant security information

##### 📊 **Enhanced JAR Impact Visualization**
- **🔧 Fixed Data Mapping**: Resolved issue where JAR charts showed "0 CVEs" despite vulnerabilities
- **Accurate CVE Counting**: Proper mapping between vulnerability IDs and dependency data
- **Color-Coded Severity**: Visual severity indicators for each JAR's vulnerability profile
- **Detailed Breakdowns**: Critical, High, Medium, Low severity counts per dependency

#### 📋 **Trend Report Capabilities**

```bash
# Generate dedicated trend analysis report
mvn bastion:trend-analysis -Dbastion.format=html

# Output: target/security-reports/bastion-trend-report-{project-name}.html
```

**Trend Report Includes:**
- 📈 **Historical Trend Chart**: JARs and CVEs evolution over multiple scans
- 🏷️ **JAR Status Tracking**: Resolved, New, and Pending vulnerable JARs
- 📊 **Conditional JAR Distribution**: Only shown when vulnerabilities exist
- 🔍 **Vulnerability Breakdown**: Detailed CVE information per JAR
- 💡 **Smart Recommendations**: Context-aware security guidance

### Report Formats

Bastion generates comprehensive reports with advanced visualizations:

#### Community Edition Reports
- **HTML**: Interactive reports with graphical dependency trees, CVE documentation tables, and trend analysis
- **Trend Report**: Dedicated trend analysis report showing historical vulnerability patterns
- **JSON**: Machine-readable format with detailed vulnerability descriptions for CI/CD integration  
- **CSV**: Enhanced data export with CVE descriptions and official documentation links

#### Commercial Edition Reports
- **All Community Formats**: Plus enhanced features with persistent historical data
- **PDF**: Executive-ready reports with comprehensive graphics and charts
- **SARIF**: Security Analysis Results Interchange Format for enterprise security tools
- **Enhanced Trend Analysis**: Advanced historical tracking with multi-project correlation

### HTML Report Features

The enhanced HTML reports include:

#### 🌳 **Graphical Dependency Tree**
- **Visual Tree Structure**: ASCII-based dependency hierarchy similar to `mvn dependency:tree`
- **Vulnerability Indicators**: Color-coded vulnerability counts and severity badges  
- **Direct vs Transitive**: Clear classification of dependency relationships
- **Risk Assessment**: Smart analysis of direct vs transitive vulnerability impact
- **File Paths**: Local Maven repository locations for each dependency

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
- **Limited References**: Maximum 3 additional reference links to prevent clutter
- **Severity Indicators**: Color-coded severity badges and CVSS scores
- **Affected Components**: Component and version information for each CVE

#### 📊 **Enhanced Analytics & Trend Analysis**
- **Dependency Statistics**: Total, vulnerable, and clean dependency counts
- **Risk Coverage**: Percentage-based risk assessment
- **Remediation Guidance**: Prioritized recommendations for vulnerability fixes
- **🆕 Historical Trend Charts**: Interactive charts showing JARs and CVEs evolution over time
- **🆕 Smart Conditional Display**: JAR distribution charts only appear when CVEs are present
- **🆕 Enhanced JAR Impact Visualization**: Accurate vulnerability mapping with detailed breakdown

```xml
<configuration>
    <reporting>
        <formats>
            <json>true</json>          <!-- API integration -->
            <html>true</html>          <!-- Human readable -->
            <pdf>true</pdf>            <!-- Executive summaries (Licensed) -->
            <sarif>true</sarif>        <!-- Security tools integration (Licensed) -->
            <csv>true</csv>            <!-- Data analysis -->
        </formats>
        
        <!-- Basic report options -->
        <includeTrends>true</includeTrends>
        <includeStatistics>true</includeStatistics>
        <includePerformanceMetrics>true</includePerformanceMetrics>
    </reporting>
</configuration>
```

### Sample Report Dashboard

The HTML report includes:
- 📈 **Vulnerability Trend Analysis**: Historical comparison with previous scans
- 🎯 **Most Impacted Dependencies**: Risk-ranked component list  
- 📊 **Detailed Scan Statistics**: JAR analysis, CVE breakdown, performance metrics
- 🔧 **Performance Insights**: Resource usage, timing breakdown, optimization tips
- 🚀 **Processing Speed**: Dependencies processed per second, cache efficiency

### Performance Metrics Dashboard

The enhanced statistics display shows:

```
📊 Comprehensive Scan Analysis
────────────────────────────────────
📦 JAR Analysis:
   ├─ Total JARs Scanned: 127
   ├─ Unique Components: 98
   └─ Duplicate Dependencies: 29

🔍 CVE Analysis:
   ├─ Total CVEs Found: 23
   ├─ Unique CVEs: 18
   ├─ CVEs with Known Exploits: 5
   ├─ Average CVSS Score: 6.7/10
   └─ Most Vulnerable Component: jackson-core:2.9.8

⚡ Performance Metrics:
   ├─ Scan Duration: 19.5 seconds
   ├─ Processing Speed: 6.5 JARs/second
   ├─ Peak Memory Usage: 384 MB
   ├─ Cache Hit Rate: 78% (234/300)
   └─ Slowest Phase: Vulnerability Analysis (65% of time)

🎯 Severity Breakdown:
   ├─ 🔴 Critical: 3 vulnerabilities
   ├─ 🟠 High: 7 vulnerabilities
   ├─ 🟡 Medium: 10 vulnerabilities
   └─ 🟢 Low: 3 vulnerabilities
```

## 🏢 How Bastion Helps Companies Track CVEs

### 1. **Centralized Vulnerability Intelligence**

**Challenge**: Companies struggle to track vulnerabilities across hundreds of applications and thousands of dependencies.

**Bastion Solution**:
- **Centralized Database**: All vulnerability data stored in enterprise PostgreSQL database
- **Cross-Project Analytics**: Identify common vulnerable dependencies across all projects
- **Executive Dashboards**: Real-time security posture visibility for management

```sql
-- Example: Find most vulnerable dependencies across organization
SELECT dependency_name, COUNT(*) as project_count, 
       AVG(critical_count) as avg_critical_vulns
FROM project_dependencies 
GROUP BY dependency_name 
ORDER BY avg_critical_vulns DESC;
```

### 2. **Automated Compliance Reporting**

**Challenge**: Meeting regulatory requirements (PCI-DSS, SOX, HIPAA) requires continuous vulnerability monitoring and documentation.

**Bastion Solution**:
- **Compliance Templates**: Pre-built reports for major frameworks
- **Audit Trails**: Complete history of vulnerability discovery and remediation
- **Automated Evidence Collection**: Generate compliance artifacts automatically

### 3. **Risk-Based Prioritization**

**Challenge**: Not all CVEs pose equal risk to your specific environment and business.

**Bastion Solution**:
- **Business Context**: Consider actual usage and exposure of vulnerable components
- **Exploitability Analysis**: Prioritize based on available exploits and attack vectors
- **CVSS+ Scoring**: Enhanced scoring incorporating business impact factors

### 4. **Team Collaboration & Accountability**

**Challenge**: Coordinating vulnerability remediation across development, security, and operations teams.

**Bastion Solution**:
- **Role-Based Notifications**: Different alerts for developers, security teams, and management
- **SLA Tracking**: Monitor time-to-resolution for different vulnerability severities
- **Integration APIs**: Connect with JIRA, ServiceNow, and other workflow tools

## 🔗 CI/CD Integration (Community Edition)

### GitHub Actions

#### Basic Security Scan

```yaml
name: Bastion Security Scan
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
        
    - name: Run Bastion Security Scan
      env:
        NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      run: |
        mvn io.github.dodogeny:bastion-maven-community-plugin:1.0.0:scan \
          -Dbastion.nvd.apiKey=${NVD_API_KEY} \
          -Dbastion.failOnCritical=true \
          -Dbastion.statistics.enabled=true
    
    - name: Upload Security Reports
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: bastion-security-reports
        path: target/security/
        retention-days: 30
```

#### Advanced GitHub Actions with JSON Storage

```yaml
name: Advanced Bastion Security Scan
on: 
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0  # Full history for trend analysis
        
    - uses: actions/setup-java@v4
      with:
        java-version: '11'
        distribution: 'temurin'
        
    - name: Cache Maven and Bastion data
      uses: actions/cache@v3
      with:
        path: |
          ~/.m2
          ${{ github.workspace }}/.bastion
        key: ${{ runner.os }}-bastion-${{ hashFiles('**/pom.xml') }}
        
    - name: Create Bastion cache directory
      run: mkdir -p .bastion
        
    - name: Run Bastion Security Scan with Trend Analysis
      env:
        NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      run: |
        mvn io.github.dodogeny:bastion-maven-community-plugin:1.0.0:scan \
          -Dbastion.nvd.apiKey=${NVD_API_KEY} \
          -Dbastion.community.storageMode=JSON_FILE \
          -Dbastion.storage.jsonFilePath=${GITHUB_WORKSPACE}/.bastion/vulnerabilities.json \
          -Dbastion.failOnCritical=true \
          -Dbastion.failOnHigh=false \
          -Dbastion.multiModule.enabled=true \
          -Dbastion.statistics.enabled=true \
          -Dbastion.reporting.includeTrends=true
          
    - name: Verify Trend Analysis Report Generated
      if: always()
      run: |
        echo "✅ Trend analysis report automatically generated during scan"
        ls -la target/bastion-reports/bastion-trend-report-*.html || echo "Trend report will be available after second scan"
    
    - name: Upload Security Reports
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: bastion-security-reports-${{ github.run_number }}
        path: |
          target/security/
          target/security-reports/
        retention-days: 90
        
    - name: Comment PR with Security Summary
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const path = 'target/security/vulnerability-report.json';
          
          if (fs.existsSync(path)) {
            const report = JSON.parse(fs.readFileSync(path, 'utf8'));
            const summary = `
          ## 🛡️ Bastion Security Scan Results
          
          - **Total Vulnerabilities**: ${report.totalVulnerabilities || 0}
          - **Critical**: ${report.criticalVulnerabilities || 0}
          - **High**: ${report.highVulnerabilities || 0}
          - **Medium**: ${report.mediumVulnerabilities || 0}
          - **Low**: ${report.lowVulnerabilities || 0}
          - **Dependencies Scanned**: ${report.totalDependencies || 0}
          
          📊 [View Detailed Report](${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID})
          `;
          
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: summary
            });
          }
```

### Jenkins Pipeline

#### Basic Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    environment {
        NVD_API_KEY = credentials('nvd-api-key')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Security Scan') {
            steps {
                sh '''
                    mvn io.github.dodogeny:bastion-maven-community-plugin:1.0.0:scan \
                      -Dbastion.nvd.apiKey=${NVD_API_KEY} \
                      -Dbastion.failOnCritical=true \
                      -Dbastion.statistics.enabled=true \
                      -Dbastion.community.storageMode=JSON_FILE \
                      -Dbastion.storage.jsonFilePath=${WORKSPACE}/bastion-vulnerabilities.json
                '''
            }
            
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'target/security',
                        reportFiles: 'vulnerability-report.html',
                        reportName: 'Bastion Security Report'
                    ])
                    
                    archiveArtifacts artifacts: 'target/security/**/*', allowEmptyArchive: true
                    archiveArtifacts artifacts: 'bastion-vulnerabilities.json', allowEmptyArchive: true
                }
                
                failure {
                    emailext (
                        subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                        body: """
                        Security scan failed for ${env.JOB_NAME} build ${env.BUILD_NUMBER}.
                        
                        Check the build log: ${env.BUILD_URL}
                        View security report: ${env.BUILD_URL}Bastion_Security_Report/
                        """,
                        to: "${env.CHANGE_AUTHOR_EMAIL},security-team@company.com"
                    )
                }
            }
        }
        
        stage('Archive Reports') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                }
            }
            steps {
                script {
                    // Trend analysis is automatically generated during scan
                    def trendReportExists = fileExists 'target/bastion-reports/bastion-trend-report-*.html'
                    if (trendReportExists) {
                        publishHTML([
                            allowMissing: false,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: 'target/bastion-reports',
                            reportFiles: 'bastion-trend-report-*.html',
                            reportName: 'Bastion Trend Analysis'
                        ])
                    } else {
                        echo "Trend analysis will be available after at least 2 scans with JSON storage"
                    }
                }
            }
        }
    }
}
```

### GitLab CI/CD

```yaml
# .gitlab-ci.yml
stages:
  - security-scan
  - report

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=${CI_PROJECT_DIR}/.m2/repository"

cache:
  paths:
    - .m2/repository/
    - .bastion/

bastion-security-scan:
  stage: security-scan
  image: maven:3.8.6-openjdk-11
  
  variables:
    NVD_API_KEY: $NVD_API_KEY
    
  before_script:
    - mkdir -p .bastion
    
  script:
    - |
      mvn io.github.dodogeny:bastion-maven-community-plugin:1.0.0:scan \
        -Dbastion.nvd.apiKey=${NVD_API_KEY} \
        -Dbastion.community.storageMode=JSON_FILE \
        -Dbastion.storage.jsonFilePath=${CI_PROJECT_DIR}/.bastion/vulnerabilities.json \
        -Dbastion.failOnCritical=false \
        -Dbastion.statistics.enabled=true \
        -Dbastion.reporting.includeTrends=true
        
  artifacts:
    when: always
    expire_in: 30 days
    paths:
      - target/security/
      - .bastion/
    reports:
      junit: target/security/vulnerability-report.xml
      
  allow_failure: false

archive-reports:
  stage: report
  image: maven:3.8.6-openjdk-11
  dependencies:
    - bastion-security-scan
    
  script:
    - |
      echo "Trend analysis reports are automatically generated during scan"
      find target/bastion-reports -name "bastion-trend-report-*.html" -ls || echo "No trend report found (needs 2+ scans)"
        
  artifacts:
    when: always
    expire_in: 90 days
    paths:
      - target/bastion-reports/
      
  only:
    - main
    - develop
```

### Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
trigger:
- main
- develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  MAVEN_CACHE_FOLDER: $(Pipeline.Workspace)/.m2/repository
  MAVEN_OPTS: '-Dmaven.repo.local=$(MAVEN_CACHE_FOLDER)'

steps:
- task: Cache@2
  inputs:
    key: 'maven | "$(Agent.OS)" | **/pom.xml'
    restoreKeys: |
      maven | "$(Agent.OS)"
      maven
    path: $(MAVEN_CACHE_FOLDER)
  displayName: Cache Maven local repo

- task: JavaToolInstaller@0
  inputs:
    versionSpec: '11'
    jdkArchitectureOption: 'x64'
    jdkSourceOption: 'PreInstalled'

- script: |
    mvn io.github.dodogeny:bastion-maven-community-plugin:1.0.0:scan \
      -Dbastion.nvd.apiKey=$(NVD_API_KEY) \
      -Dbastion.community.storageMode=JSON_FILE \
      -Dbastion.storage.jsonFilePath=$(Agent.TempDirectory)/bastion-vulnerabilities.json \
      -Dbastion.failOnCritical=true \
      -Dbastion.statistics.enabled=true
  displayName: 'Run Bastion Security Scan'
  env:
    NVD_API_KEY: $(nvd-api-key)

- task: PublishHtmlReport@1
  condition: always()
  inputs:
    reportDir: 'target/security'
    tabName: 'Bastion Security Report'
    
- task: PublishTestResults@2
  condition: always()
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: 'target/security/vulnerability-report.xml'
    testRunTitle: 'Security Vulnerabilities'
    
- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    pathToPublish: 'target/security'
    artifactName: 'bastion-security-reports'
```

### Docker Integration

```dockerfile
# Dockerfile for security scanning
FROM maven:3.8.6-openjdk-11 AS security-scanner

WORKDIR /app
COPY pom.xml .
COPY src ./src

# Install and run Bastion security scan
RUN mvn io.github.dodogeny:bastion-maven-community-plugin:1.0.0:scan \
    -Dbastion.community.storageMode=JSON_FILE \
    -Dbastion.storage.jsonFilePath=/app/vulnerabilities.json \
    -Dbastion.statistics.enabled=true

# Export reports
FROM nginx:alpine AS report-server
COPY --from=security-scanner /app/target/security /usr/share/nginx/html/security
COPY --from=security-scanner /app/vulnerabilities.json /usr/share/nginx/html/
EXPOSE 80
```

## 📄 JSON File Storage

### Overview

Bastion supports JSON file-based storage as an alternative to database storage, perfect for simpler deployments or when database setup isn't feasible. JSON storage includes full trend analysis and historical tracking capabilities.

### Benefits
- **No Database Setup**: Zero configuration - just specify a file path
- **Version Control Friendly**: JSON files can be committed to source control for audit trails
- **Portable**: Easy to backup, move, and analyze vulnerability data
- **Trend Analysis**: Full historical trend tracking across scan executions
- **Human Readable**: Direct file access for manual analysis and reporting

### Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Enable JSON file storage -->
        <storage>
            <useJsonFile>true</useJsonFile>
            <jsonFilePath>${project.build.directory}/bastion-vulnerabilities.json</jsonFilePath>
        </storage>
        
        <!-- Optional: Purge configuration -->
        <purgeBeforeScan>false</purgeBeforeScan>
        <purge>
            <projectOnly>true</projectOnly>
            <olderThanDays>30</olderThanDays>
            <dryRun>false</dryRun>
        </purge>
    </configuration>
</plugin>
```

### Usage Examples

```bash
# Enable JSON storage with default path
mvn bastion:scan -Dbastion.storage.useJsonFile=true

# Custom JSON file location
mvn bastion:scan \
  -Dbastion.storage.useJsonFile=true \
  -Dbastion.storage.jsonFilePath=/path/to/custom-vulnerabilities.json

# JSON storage with purge before scan
mvn bastion:scan \
  -Dbastion.storage.useJsonFile=true \
  -Dbastion.purgeBeforeScan=true

# Preview what would be purged (dry run)
mvn bastion:scan \
  -Dbastion.storage.useJsonFile=true \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.dryRun=true
```

### JSON File Structure

```json
{
  "created": "2024-01-01T10:00:00",
  "lastUpdated": "2024-01-15T14:30:00",
  "scanHistory": [
    {
      "timestamp": "2024-01-15T14:30:00",
      "projectInfo": {
        "groupId": "com.example",
        "artifactId": "my-app",
        "version": "1.0.0"
      },
      "scanResult": {
        "totalVulnerabilities": 5,
        "criticalVulnerabilities": 1,
        "highVulnerabilities": 2,
        "mediumVulnerabilities": 2,
        "lowVulnerabilities": 0,
        "totalDependencies": 127,
        "scanDurationMs": 15420,
        "vulnerabilities": [...]
      }
    }
  ]
}
```

### Trend Analysis

When using JSON storage, Bastion automatically provides vulnerability trend analysis:

```
📈 Vulnerability Trend Analysis (vs Previous Scan)
─────────────────────────────────────────────────
📅 Previous Scan: 2024-01-14 09:15:30
📊 Historical Scans: 12

🔍 Total Vulnerabilities: ⬇️ -3
🔴 Critical: ➡️ 0
🟠 High: ⬇️ -2
🟡 Medium: ⬇️ -1
🟢 Low: ➡️ 0
```

## 🗑️ Data Purge Management

### Overview

Bastion includes comprehensive data purge functionality to manage historical vulnerability data, available for both database and JSON file storage modes.

### Purge Options

- **Complete Purge**: Remove all vulnerability data
- **Project-Specific**: Purge only current project data
- **Time-Based**: Remove records older than specified days
- **Dry Run**: Preview operations without making changes

### Configuration Examples

```xml
<configuration>
    <purgeBeforeScan>true</purgeBeforeScan>
    <purge>
        <!-- Confirmation settings -->
        <force>false</force>              <!-- Skip interactive confirmation -->
        <confirm>false</confirm>          <!-- Auto-confirm operations -->
        
        <!-- Scope settings -->
        <projectOnly>true</projectOnly>   <!-- Only purge current project -->
        <olderThanDays>30</olderThanDays> <!-- Only purge records > 30 days -->
        
        <!-- Safety settings -->
        <dryRun>false</dryRun>           <!-- Preview without executing -->
    </purge>
</configuration>
```

### Purge Commands

```bash
# Purge all data before scan (interactive confirmation)
mvn bastion:scan -Dbastion.purgeBeforeScan=true

# Force purge without confirmation
mvn bastion:scan \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.force=true

# Purge only current project data
mvn bastion:scan \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.projectOnly=true

# Purge records older than 30 days
mvn bastion:scan \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.olderThanDays=30

# Dry run - preview what would be deleted
mvn bastion:scan \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.dryRun=true

# JSON file: Delete entire file
mvn bastion:scan \
  -Dbastion.storage.useJsonFile=true \
  -Dbastion.purgeBeforeScan=true

# JSON file: Remove only project entries
mvn bastion:scan \
  -Dbastion.storage.useJsonFile=true \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.projectOnly=true
```

### Purge Safety Features

- **Interactive Confirmation**: Type 'DELETE' to confirm destructive operations
- **Impact Analysis**: Shows exactly what will be deleted before confirmation
- **Dry Run Mode**: Preview operations without making changes
- **Granular Control**: Project-only and time-based filtering options
- **JSON File Backup**: Automatic backup before major operations

### Sample Purge Output

```
🗑️ Bastion Database Purge Utility
=====================================

📊 Purge Scope Configuration:
  • Scope: Current project only (my-app)
  • Age Filter: ALL records (no age restriction)  
  • Mode: DESTRUCTIVE (will permanently delete data)

📊 Impact Analysis:
  • JSON entries for this project: 8
  • Action: Remove project entries from JSON file

⚠️ WARNING: This operation will PERMANENTLY DELETE vulnerability data!
⚠️ This action CANNOT be undone!

Are you sure you want to continue? Type 'DELETE' to confirm: DELETE

🗑️ Performing JSON file purge...
✅ Deleted 8 entries for project: my-app

🎉 JSON purge operation completed successfully!
📊 Summary:
  • Entries deleted: 8
  • Remaining entries: 15
  • Operation duration: 142ms
```

## 🔧 Advanced Configuration

### Custom Vulnerability Exclusions

```xml
<configuration>
    <exclusions>
        <!-- Temporary exclusions with expiry -->
        <exclusion>
            <cveId>CVE-2021-44228</cveId>
            <reason>Mitigated by firewall rules</reason>
            <expiryDate>2024-06-01</expiryDate>
            <approvedBy>security-team@company.com</approvedBy>
        </exclusion>
        
        <!-- Scope-based exclusions -->
        <scopeExclusions>
            <scope>test</scope>           <!-- Exclude test dependencies -->
            <scope>provided</scope>       <!-- Exclude provided deps -->
        </scopeExclusions>
        
        <!-- Dependency exclusions -->
        <dependencyExclusions>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>legacy-lib</artifactId>
                <reason>End-of-life, scheduled for removal</reason>
            </dependency>
        </dependencyExclusions>
    </exclusions>
</configuration>
```

### Performance Monitoring

```xml
<configuration>
    <monitoring>
        <performanceMetrics>true</performanceMetrics>
        <slowQueryThreshold>5000</slowQueryThreshold>     <!-- 5 seconds -->
        <memoryUsageTracking>true</memoryUsageTracking>
        
        <!-- Integration with monitoring systems -->
        <metrics>
            <prometheus>
                <enabled>true</enabled>
                <endpoint>/metrics</endpoint>
            </prometheus>
            <jmx>
                <enabled>true</enabled>
                <port>9999</port>
            </jmx>
        </metrics>
    </monitoring>
</configuration>
```

## 📚 API Reference

### Maven Goals

Bastion Community Edition provides **one Maven goal**:

| Goal | Description | Phase |
|------|-------------|-------|
| `scan` | Run complete vulnerability scan with integrated trend analysis | verify |

**Note:** Trend analysis is automatically included in the scan goal when using JSON file storage mode.

### 📋 Complete Configuration Parameters Reference

> **📦 Community Edition** | **🏢 Enterprise Edition** | **📦🏢 Both Editions**

All parameters can be configured in your `pom.xml` `<configuration>` section or passed as Maven properties (`-Dproperty=value`).

---

## Core Configuration

| Parameter | Property Key | Type | Default | Description | Edition |
|-----------|--------------|------|---------|-------------|---------|
| `skip` | `bastion.skip` | boolean | `false` | Skip vulnerability scan entirely | 📦🏢 |
| `failOnError` | `bastion.failOnError` | boolean | `true` | Fail build when vulnerabilities exceed threshold | 📦🏢 |
| `severityThreshold` | `bastion.severityThreshold` | String | `MEDIUM` | Build failure threshold: `CRITICAL`, `HIGH`, `MEDIUM` | 📦🏢 |

## Output & Reporting

| Parameter | Property Key | Type | Default | Description | Edition |
|-----------|--------------|------|---------|-------------|---------|
| `outputDirectory` | `bastion.outputDirectory` | File | `${project.build.directory}/bastion-reports` | Directory for generated reports | 📦🏢 |
| `reportFormats` | `bastion.reportFormats` | String | `HTML,JSON` | Report formats: HTML,JSON,CSV (📦) + PDF,SARIF (🏢) | 📦🏢 |

## Scanner Configuration

| Parameter | Property Key | Type | Default | Description | Edition |
|-----------|--------------|------|---------|-------------|---------|
| `nvdApiKey` | `bastion.nvd.apiKey` | String | `null` | NVD API key ([Get Free Key](https://nvd.nist.gov/developers/request-an-api-key)) | 📦🏢 |
| `scannerTimeout` | `bastion.scanner.timeout` | int | `300000` | Scanner timeout in milliseconds (5 minutes) | 📦🏢 |
| `enableMultiModule` | `bastion.enableMultiModule` | boolean | `true` | Enable multi-module project scanning | 📦🏢 |

## Storage Configuration

| Parameter | Property Key | Type | Default | Description | Edition |
|-----------|--------------|------|---------|-------------|---------|
| `communityStorageMode` | `bastion.community.storageMode` | String | `IN_MEMORY` | Storage mode: `IN_MEMORY` or `JSON_FILE` | 📦🏢 |
| `useJsonFileStorage` | `bastion.storage.useJsonFile` | boolean | `false` | Alternative way to enable JSON file storage | 📦🏢 |
| `jsonFilePath` | `bastion.storage.jsonFilePath` | String | `${project.build.directory}/bastion-vulnerabilities.json` | Path for JSON file storage | 📦🏢 |

## Database Configuration (Enterprise Only)

| Parameter | Property Key | Type | Default | Description | Edition |
|-----------|--------------|------|---------|-------------|---------|
| `databaseUrl` | `bastion.database.url` | String | `null` | Database URL (e.g., `jdbc:postgresql://localhost:5432/bastion`) | 🏢 |
| `databaseUsername` | `bastion.database.username` | String | `null` | Database username | 🏢 |
| `databasePassword` | `bastion.database.password` | String | `null` | Database password | 🏢 |

## Email Notifications (Enterprise Only)

| Parameter | Property Key | Type | Default | Description | Edition |
|-----------|--------------|------|---------|-------------|---------|
| `emailEnabled` | `bastion.email.enabled` | boolean | `false` | Enable email notifications for vulnerabilities | 🏢 |
| `smtpHost` | `bastion.email.smtp.host` | String | `null` | SMTP server hostname | 🏢 |
| `smtpPort` | `bastion.email.smtp.port` | int | `587` | SMTP server port | 🏢 |
| `smtpUsername` | `bastion.email.smtp.username` | String | `null` | SMTP authentication username | 🏢 |
| `smtpPassword` | `bastion.email.smtp.password` | String | `null` | SMTP authentication password | 🏢 |
| `smtpTls` | `bastion.email.smtp.tls` | boolean | `true` | Enable TLS encryption for SMTP | 🏢 |
| `emailRecipients` | `bastion.email.recipients` | String | `null` | Comma-separated list of email recipients | 🏢 |
| `emailSeverityThreshold` | `bastion.email.severityThreshold` | String | `HIGH` | Minimum severity level for email alerts | 🏢 |

## Enterprise Licensing (Enterprise Only)

| Parameter | Property Key | Type | Default | Description | Edition |
|-----------|--------------|------|---------|-------------|---------|
| `apiKey` | `bastion.apiKey` | String | `null` | Enterprise license API key from [LemonSqueezy](https://bastionplugin.lemonsqueezy.com) | 🏢 |

## Data Management & Purge

| Parameter | Property Key | Type | Default | Description | Edition |
|-----------|--------------|------|---------|-------------|---------|
| `purgeBeforeScan` | `bastion.purgeBeforeScan` | boolean | `false` | Purge existing data before scanning | 📦🏢 |
| `force` | `bastion.purge.force` | boolean | `false` | Skip confirmation prompts for purge | 📦🏢 |
| `confirmPurge` | `bastion.purge.confirm` | boolean | `false` | Auto-confirm purge operations | 📦🏢 |
| `projectOnly` | `bastion.purge.projectOnly` | boolean | `false` | Purge only current project data | 📦🏢 |
| `olderThanDays` | `bastion.purge.olderThanDays` | int | `0` | Purge records older than N days (0 = all) | 📦🏢 |
| `dryRun` | `bastion.purge.dryRun` | boolean | `false` | Preview purge operations without execution | 📦🏢 |

---

## 🚀 Quick Configuration Examples

#### Usage Examples

**Command Line:**
```bash
# Basic scan
mvn bastion:scan

# With all common options
mvn bastion:scan \
  -Dbastion.nvd.apiKey=${NVD_API_KEY} \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.storage.jsonFilePath=./vulnerabilities.json \
  -Dbastion.severityThreshold=HIGH \
  -Dbastion.enableMultiModule=true \
  -Dbastion.scanner.timeout=600000

# Skip scan
mvn bastion:scan -Dbastion.skip=true

# Purge before scan
mvn bastion:scan \
  -Dbastion.community.storageMode=JSON_FILE \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.projectOnly=true \
  -Dbastion.purge.dryRun=true
```

## 🔐 Security & Privacy

Bastion is designed with security-first principles:

- **No Data Exfiltration**: All vulnerability data stays within your infrastructure  
- **Encrypted Communication**: TLS/SSL for all external API calls
- **Secure Credential Storage**: Integration with Maven settings encryption
- **Audit Logging**: Complete audit trail of all security scanning activities
- **Role-Based Access**: Fine-grained permissions for different user roles

## 🆘 Support & Community

### Community Support
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/jdneemuth/bastion-maven-community-plugin/issues)
- **Documentation**: Full documentation and examples in this README
- **Community Forum**: Stack Overflow with tag `bastion-maven-plugin`

### Enterprise Support
- **Email**: enterprise-support@dodogeny.mu
- **Response Time**: 24 hours for critical issues  
- **Priority Support**: Available for licensed customers only

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Bastion Maven Plugin Community** - Your free, open-source fortress against security vulnerabilities.

*Developed with ❤️ by [Dodogeny](https://dodogeny.mu) in Mauritius* 🇲🇺

**Ready for Enterprise Features?** Upgrade to [Bastion Enterprise Edition](https://bastionplugin.lemonsqueezy.com) for advanced security capabilities.

---

