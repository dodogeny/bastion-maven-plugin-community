# Bastion Maven Plugin - Installation Guide

This guide covers installation methods for both Community and Commercial editions.

## Prerequisites

- **Java**: JDK 8 or higher
- **Maven**: 3.6.0 or higher
- **Memory**: 1GB+ RAM for large enterprise projects

## Community Edition Installation (Free)

### Basic Setup

Add the plugin to your `pom.xml`:

```xml
<plugin>
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Community Edition settings (default) -->
        
        <!-- In-memory database configuration -->
        <inMemoryDatabase>
            <maxProjects>50</maxProjects>
            <maxSessionsPerProject>10</maxSessionsPerProject>
            <sessionTtlHours>24</sessionTtlHours>
        </inMemoryDatabase>
        
        <!-- Report generation -->
        <reporting>
            <formats>
                <html>true</html>
                <json>true</json>
                <csv>true</csv>
            </formats>
            <includeTrends>true</includeTrends>
            <includeStatistics>true</includeStatistics>
        </reporting>
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

### Run Your First Scan

```bash
# Community Edition (default)
mvn bastion:scan

# With detailed output
mvn bastion:scan -X
```

### Verify Installation

Check that reports are generated in `target/security-reports/`:
- `bastion-report-{project-name}.html` - Interactive HTML report with dependency tree
- `bastion-report-{project-name}.json` - Machine-readable JSON with CVE descriptions
- `bastion-report-{project-name}.csv` - Enhanced CSV with documentation links

## Commercial Edition Installation

### Step 1: Get Commercial License

1. **Purchase License** at https://bastion.dodogeny.mu
2. **Receive API Key** via email after purchase
3. **Verify License** is active in your LemonSqueezy dashboard

### Step 2: Configure Commercial Edition

```xml
<plugin>
    <groupId>mu.dodogeny</groupId>
    <artifactId>bastion-maven-plugin</artifactId>
    <version>1.0.0</version>
    <configuration>
        <!-- Commercial Edition configuration -->
        <apiKey>${env.BASTION_API_KEY}</apiKey>
        
        <!-- Enhanced database options -->
        <database>
            <type>h2</type> <!-- or postgresql, mysql -->
            <path>${user.home}/.m2/bastion-security-cache/vulnerability-db</path>
            <username>bastion</username>
            <password>${env.DB_PASSWORD}</password>
        </database>
        
        <!-- Advanced reporting -->
        <reporting>
            <formats>
                <html>true</html>
                <json>true</json>
                <csv>true</csv>
                <pdf>true</pdf>     <!-- Commercial only -->
                <sarif>true</sarif>  <!-- Commercial only -->
            </formats>
            <includeTrends>true</includeTrends>
            <includeHistoricalAnalysis>true</includeHistoricalAnalysis>
        </reporting>
        
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
            </recipients>
            <alertOn>
                <critical>true</critical>
                <high>true</high>
            </alertOn>
        </notifications>
    </configuration>
</plugin>
```

### Step 3: Set Environment Variables

```bash
# Required for Commercial Edition
export BASTION_API_KEY="your_lemonsqueezy_api_key"
export DB_PASSWORD="your_secure_database_password"

# Optional for email notifications
export SMTP_USER="security-scanner@company.com"
export SMTP_PASS="secure_app_password"
```

### Step 4: Run Commercial Edition

```bash
# Commercial Edition
```

Look for the commercial activation message:
```
✅ LemonSqueezy license validated successfully
💼 Bastion Commercial Edition activated
🚀 All premium features unlocked
```

## Method 2: Direct Download

### Download Distribution

1. Download the appropriate distribution:
   - **Windows**: `bastion-maven-plugin-${project.version}-bin.zip`
   - **Unix/Linux/macOS**: `bastion-maven-plugin-${project.version}-bin-unix.tar.gz`

2. **Extract Archive**

   ```bash
   # For Unix/Linux/macOS
   tar -xzf bastion-maven-plugin-${project.version}-bin-unix.tar.gz
   
   # For Windows (using PowerShell)
   Expand-Archive bastion-maven-plugin-${project.version}-bin.zip
   ```

3. **Run Installation Script**

   ```bash
   cd bastion-maven-plugin-${project.version}
   ./bin/install.sh
   ```

### Manual Installation

If you prefer manual installation:

1. **Copy JARs to Local Repository**

   ```bash
   cp lib/*.jar ~/.m2/repository/mu/dodogeny/bastion-maven-plugin/${project.version}/
   ```

2. **Update Your Project POM**

   Add the plugin dependency as shown in Method 1.

## Method 3: Build from Source

### Prerequisites

- Java JDK 8 or higher
- Apache Maven 3.6.0 or higher
- Git

### Build Steps

1. **Clone Repository**

   ```bash
   git clone https://github.com/dodogeny/bastion-maven-plugin.git
   cd bastion-maven-plugin
   ```

2. **Build Project**

   ```bash
   mvn clean install
   ```

3. **Install to Local Repository**

   ```bash
   mvn install:install-file \
     -Dfile=plugin/target/bastion-maven-plugin-${project.version}.jar \
     -DgroupId=mu.dodogeny \
     -DartifactId=bastion-maven-plugin \
     -Dversion=${project.version} \
     -Dpackaging=maven-plugin
   ```

## Commercial Edition Setup (LemonSqueezy Only)

### LemonSqueezy License Purchase

**Important**: All commercial licenses are exclusively managed through LemonSqueezy.

1. **Purchase License**

   Visit [https://bastion.lemonsqueezy.com](https://bastion.lemonsqueezy.com) to purchase a commercial license.

2. **Receive API Key**

   After purchase, you'll receive your LemonSqueezy API key via email immediately.

3. **Configure API Key**

   **Method 1: Environment Variable (Recommended)**
   ```bash
   export BASTION_API_KEY="bsk_live_abc123..."
   ```

   **Method 2: Maven Configuration**
   ```xml
   <configuration>
       <apiKey>${env.BASTION_API_KEY}</apiKey>
       <licenseProvider>lemonsqueezy</licenseProvider>
   </configuration>
   ```

4. **Verify Commercial Features**

   ```bash
   mvn bastion:scan -Dbastion.apiKey=bsk_live_abc123...
   ```

   Look for confirmation message:
   ```
   ✅ LemonSqueezy license validated successfully
   💼 Bastion Commercial Edition activated
   🚀 All premium features unlocked
   ```

### LemonSqueezy Benefits

- **Instant Activation**: No manual license files needed
- **Global Access**: Use your license from any development environment
- **Automatic Renewal**: Subscription management handled by LemonSqueezy
- **Secure Payment**: Enterprise-grade payment processing
- **24/7 Support**: Direct access to LemonSqueezy support portal

## Configuration

### Environment Variables

```bash
# LemonSqueezy API key for commercial edition
export BASTION_API_KEY="bsk_live_abc123..."

# Optional: Increase memory for large projects  
export MAVEN_OPTS="-Xmx4g -XX:MaxMetaspaceSize=512m"
```

### System Properties

```bash
# Common system properties
mvn bastion:scan \
  -Dbastion.outputDirectory=./security-reports \
  -Dbastion.reportFormats=HTML,JSON,PDF \
  -Dbastion.severityThreshold=HIGH

# JSON file storage (alternative to database)
mvn bastion:scan \
  -Dbastion.storage.useJsonFile=true \
  -Dbastion.storage.jsonFilePath=./vulnerability-data.json

# Data purge operations
mvn bastion:scan \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.projectOnly=true \
  -Dbastion.purge.dryRun=true
```

## Verification

### Test Installation

1. **Check Plugin Recognition**

   ```bash
   mvn help:describe -Dplugin=mu.dodogeny:bastion-maven-plugin
   ```

2. **Run Help Goal**

   ```bash
   mvn bastion:help
   ```

3. **Run Test Scan**

   ```bash
   mvn bastion:scan -Dbastion.skip=false
   ```

### Expected Output

```
[INFO] --- bastion-maven-plugin:${project.version}:scan (default-cli) ---
[INFO] 🛡️  Starting Bastion vulnerability scan (Open Source Edition)...
[INFO] Project: test-project
[INFO] Multi-module enabled: false
[INFO] Scanning project dependencies...
[INFO] Scan completed successfully!
[INFO] Total vulnerabilities found: 0
[INFO] Generated HTML report: target/bastion-reports/bastion-report-test-project.html
```

## Troubleshooting

### Common Issues

**Plugin not found:**
```
[ERROR] Plugin mu.dodogeny:bastion-maven-plugin:${project.version} not found
```
**Solution:** Ensure the plugin is available in Maven Central or your local repository.

**Out of memory during scan:**
```
java.lang.OutOfMemoryError: Java heap space
```
**Solution:** Increase heap size:
```bash
export MAVEN_OPTS="-Xmx4g"
```

**LemonSqueezy license validation failed:**
```
[ERROR] LemonSqueezy license validation failed
```
**Solution:** 
1. Verify API key is correct
2. Check internet connection
3. Ensure subscription is active in LemonSqueezy dashboard

### LemonSqueezy Payment Methods

LemonSqueezy supports various payment methods for global accessibility:

- **Credit Cards**: Visa, MasterCard, American Express
- **Digital Wallets**: PayPal, Apple Pay, Google Pay  
- **Bank Transfers**: Available in supported regions
- **Cryptocurrencies**: Bitcoin, Ethereum (in select regions)
- **International**: Multi-currency support with automatic conversion

### LemonSqueezy Account Management

After purchase, you can manage your subscription through the LemonSqueezy customer portal:

1. **Access Customer Portal**
   ```bash
   # Visit your customer portal (link provided in purchase email)
   https://app.lemonsqueezy.com/my-orders
   ```

2. **Download Invoice**
   - Access billing history
   - Download PDF invoices for expense reporting
   - View subscription details and renewal dates

3. **Manage Subscription**
   - Upgrade/downgrade plans
   - Update payment methods
   - Cancel subscription if needed
   - View usage analytics

### Getting Help

- **Documentation**: [https://docs.dodogeny.mu/bastion](https://docs.dodogeny.mu/bastion)
- **Community Support**: [GitHub Issues](https://github.com/dodogeny/bastion-maven-plugin/issues)
- **Enterprise Support**: enterprise@dodogeny.mu
- **LemonSqueezy Support**: [https://help.lemonsqueezy.com](https://help.lemonsqueezy.com)

## Uninstallation

### Remove Plugin from Project

1. Remove the plugin declaration from your `pom.xml`
2. Clean build artifacts: `mvn clean`

### Remove from Local Repository

```bash
rm -rf ~/.m2/repository/mu/dodogeny/bastion-maven-plugin
```

### Using Uninstall Script

```bash
./bin/uninstall.sh
```

---

**Installation complete!** You're now ready to scan for vulnerabilities with Bastion Maven Plugin.