# Bastion Maven Plugin Community

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/mu.dodogeny/bastion-maven-plugin-community/badge.svg)](https://maven-badges.herokuapp.com/maven-central/mu.dodogeny/bastion-maven-plugin-community)
[![Build Status](https://github.com/dodogeny/bastion-maven-plugin-community/workflows/CI/badge.svg)](https://github.com/dodogeny/bastion-maven-plugin-community/actions)
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
# Community Edition - Free vulnerability scanning
mvn mu.dodogeny:bastion-maven-plugin-community:1.0.0:scan
```

Reports will be generated in `target/security/` directory.

**Community Features Included:**
- OWASP Dependency-Check vulnerability scanning
- HTML, JSON, and CSV reports with graphical dependency trees
- Historical trend analysis and performance metrics
- In-memory database or JSON file storage options
- Multi-module project support

## 🛠️ Available Maven Goals

Bastion provides multiple Maven goals for comprehensive security management:

```bash
# 🔍 Primary scanning goal
mvn bastion:scan

# 📈 Trend analysis with historical tracking
mvn bastion:trend-analysis

# 💼 Commercial Edition with LemonSqueezy API key
mvn bastion:scan -Dbastion.apiKey=YOUR_LEMONSQUEEZY_API_KEY

# 🗑️ Database purge functionality (integrated into scan goal)
mvn bastion:scan -Dbastion.purgeBeforeScan=true

# 📄 Community Edition - JSON file storage mode
mvn bastion:scan -Dbastion.community.storageMode=JSON_FILE

# 📄 Community Edition - In-memory database mode (default)
mvn bastion:scan -Dbastion.community.storageMode=IN_MEMORY

# 🔑 NVD API key for enhanced scanning
mvn bastion:scan -Dbastion.nvd.apiKey=YOUR_NVD_API_KEY

# 📊 Generate HTML trend analysis report
mvn bastion:trend-analysis -Dbastion.format=html

# 📄 Generate JSON trend analysis report  
mvn bastion:trend-analysis -Dbastion.format=json
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

#### Step 1: Purchase Enterprise License

Visit our LemonSqueezy store to purchase your enterprise license:

```bash
# Open in your browser
https://bastionplugin.lemonsqueezy.com
```

**Available Plans:**
- **Monthly Subscription**: $29/month per team
- **Annual Subscription**: $290/year per team (17% savings)

#### Step 2: Update Your Project Configuration

Replace the Community Edition plugin with Enterprise Edition:

```xml
<!-- Remove Community Edition -->
<!-- 
<plugin>
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-community</artifactId>
    <version>1.0.0</version>
</plugin>
-->

<!-- Add Enterprise Edition -->
<plugin>
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Enable Enterprise features -->
        <openSourceMode>false</openSourceMode>
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

#### Step 4: Verify Enterprise Activation

Run a scan to verify your enterprise license:

```bash
mvn mu.dodogeny:bastion-maven-plugin-enterprise:1.0.0:scan
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

Enterprise customers get priority support:

- **Email Support**: enterprise-support@dodogeny.mu
- **Response Time**: 24 hours for critical issues
- **Dedicated Slack Channel**: Available for annual subscribers
- **Migration Assistance**: Help migrating from Community to Enterprise

### 📊 Enterprise Reporting Features

Unlock advanced reporting capabilities:

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
     <groupId>mu.dodogeny</groupId>
     <artifactId>bastion-maven-plugin-enterprise</artifactId>
     <version>1.0.0</version>
     <configuration>
       <openSourceMode>false</openSourceMode>
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
mvn bastion:scan -Dbastion.openSourceMode=false

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
     <groupId>mu.dodogeny</groupId>
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
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Community Edition (default) -->
        <openSourceMode>true</openSourceMode>
        
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
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Community Edition -->
        <openSourceMode>true</openSourceMode>
        
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
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <openSourceMode>false</openSourceMode>
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
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <openSourceMode>false</openSourceMode>
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
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <openSourceMode>false</openSourceMode>
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
mvn bastion:scan -Dbastion.openSourceMode=false
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
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-enterprise</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- LemonSqueezy License Configuration -->
        <openSourceMode>false</openSourceMode>
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
    <groupId>mu.dodogeny</groupId>
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
    <groupId>mu.dodogeny</groupId>
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
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        SMTP_USER: ${{ secrets.SMTP_USER }}
        SMTP_PASS: ${{ secrets.SMTP_PASS }}
      run: |
        mvn mu.dodogeny:bastion-maven-plugin-enterprise:1.0.0:scan \
          -Dbastion.notifications.enabled=true \
          -Dbastion.failOnCritical=true \
          -Dbastion.apiKey=${BASTION_API_KEY}
    
    - name: Upload Security Reports
      uses: actions/upload-artifact@v3
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
        SNYK_TOKEN = credentials('snyk-api-token')
        SMTP_USER = credentials('smtp-username')
        SMTP_PASS = credentials('smtp-password')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    mvn mu.dodogeny:bastion-maven-plugin-enterprise:1.0.0:scan \
                      -Dbastion.notifications.enabled=true \
                      -Dbastion.database.type=postgresql \
                      -Dbastion.statistics.enabled=true
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
                        reportName: 'Security Scan Report'
                    ])
                }
            }
        }
    }
}
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
    <groupId>mu.dodogeny</groupId>
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

| Goal | Description | Phase |
|------|-------------|-------|
| `scan` | Run complete vulnerability scan | verify |
| `trend-analysis` | Generate historical trend analysis report | post-integration-test |
| `report` | Generate reports from existing data | post-integration-test |
| `update` | Update vulnerability databases | initialize |
| `clean-cache` | Clear cached vulnerability data | clean |

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `openSourceMode` | boolean | true | Enable Community Edition (false for Commercial) |
| `apiKey` | String | null | LemonSqueezy API key for commercial edition |
| `nvdApiKey` | String | null | NVD API key for enhanced scanning |
| `failOnCritical` | boolean | true | Fail build on critical vulnerabilities |
| `failOnHigh` | boolean | false | Fail build on high severity vulnerabilities |
| `maxAllowedVulnerabilities` | int | 0 | Maximum total vulnerabilities allowed |
| `scanners` | List | ["owasp"] | Vulnerability scanners to use |
| `multiModule.enabled` | boolean | false | Enable multi-module scanning |
| `statistics.enabled` | boolean | true | Enable comprehensive scan statistics |
| `statistics.includePerformanceMetrics` | boolean | true | Include performance breakdown |
| **Community Edition** | | | |
| `communityStorageMode` | String | IN_MEMORY | Storage mode (IN_MEMORY, JSON_FILE) |
| `jsonFilePath` | String | target/bastion-vulnerabilities.json | JSON storage file path |
| **Commercial Edition** | | | |
| `database.type` | String | "h2" | Database type (h2, postgresql, mysql) |
| `database.url` | String | null | Database connection URL |
| `database.username` | String | null | Database username |
| `database.password` | String | null | Database password |
| `database.connectionPoolSize` | int | 10 | Connection pool size |
| `notifications.enabled` | boolean | false | Enable email notifications |
| `notifications.alertOn.critical` | boolean | true | Send alerts for critical CVEs |
| `reporting.formats.pdf` | boolean | false | Generate PDF reports |
| `reporting.formats.sarif` | boolean | false | Generate SARIF reports |
| `storage.useJsonFile` | boolean | false | Use JSON file instead of database |
| `storage.jsonFilePath` | String | target/bastion-vulnerabilities.json | JSON storage file path |
| `purgeBeforeScan` | boolean | false | Purge existing data before scanning |
| `purge.force` | boolean | false | Skip confirmation prompt for purge operations |
| `purge.projectOnly` | boolean | false | Purge only current project data |
| `purge.olderThanDays` | int | 0 | Purge only records older than specified days |
| `purge.dryRun` | boolean | false | Preview purge operations without executing |

## 🔐 Security & Privacy

Bastion is designed with security-first principles:

- **No Data Exfiltration**: All vulnerability data stays within your infrastructure  
- **Encrypted Communication**: TLS/SSL for all external API calls
- **Secure Credential Storage**: Integration with Maven settings encryption
- **Audit Logging**: Complete audit trail of all security scanning activities
- **Role-Based Access**: Fine-grained permissions for different user roles

## 🆘 Support & Community

### Community Support
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/jdneemuth/bastion-maven-plugin-community/issues)
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

