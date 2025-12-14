# Bastion Maven Plugin - Quick Start Guide

## 🚀 Quick Integration (5 Minutes)

### Step 1: Add Plugin to Your `pom.xml`

```xml
<build>
    <plugins>
        <plugin>
            <groupId>io.github.dodogeny</groupId>
            <artifactId>bastion-maven-community-plugin</artifactId>
            <version>1.2.1</version>
            <executions>
                <execution>
                    <id>security-scan</id>
                    <goals>
                        <goal>scan</goal>
                    </goals>
                    <phase>verify</phase>
                </execution>
            </executions>
            <configuration>
                <!-- Basic Configuration -->
                <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
                <autoUpdate>true</autoUpdate>
                <failOnError>false</failOnError>

                <!-- Report Configuration -->
                <reportFormats>HTML,JSON</reportFormats>
                <outputDirectory>${project.build.directory}/bastion-reports</outputDirectory>
            </configuration>
        </plugin>
    </plugins>
</build>
```

### Step 2: Get NVD API Key (Recommended)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Register for a free API key
3. Set environment variable:
   ```bash
   export NVD_API_KEY=your-api-key-here
   ```

### Step 3: Run Your First Scan

```bash
# Run security scan during build
mvn clean verify

# Or run scan directly
mvn io.github.dodogeny:bastion-maven-community-plugin:1.2.1:scan \
  -Dbastion.nvd.apiKey=YOUR_API_KEY
```

### Step 4: View Results

Reports are generated in `target/bastion-reports/`:
- **HTML Report**: `bastion-report-{project-name}.html`
- **JSON Report**: `bastion-report-{project-name}.json`

---

## 📋 Common Integration Patterns

### Pattern 1: Basic CI/CD Integration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.2.1</version>
    <executions>
        <execution>
            <goals>
                <goal>scan</goal>
            </goals>
            <phase>verify</phase>
        </execution>
    </executions>
    <configuration>
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
        <autoUpdate>true</autoUpdate>
        <failOnError>true</failOnError>
        <severityThreshold>HIGH</severityThreshold>
    </configuration>
</plugin>
```

**Usage:**
```bash
mvn clean verify
```

### Pattern 2: Manual On-Demand Scanning

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-community-plugin</artifactId>
    <version>1.2.1</version>
    <!-- No executions - only run when explicitly called -->
    <configuration>
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
        <reportFormats>HTML,JSON</reportFormats>
    </configuration>
</plugin>
```

**Usage:**
```bash
# Run scan manually
mvn bastion-maven-community-plugin:scan

# Or with full coordinates
mvn io.github.dodogeny:bastion-maven-community-plugin:1.2.1:scan
```

### Pattern 3: Multi-Module Projects

```xml
<!-- In parent pom.xml -->
<build>
    <pluginManagement>
        <plugins>
            <plugin>
                <groupId>io.github.dodogeny</groupId>
                <artifactId>bastion-maven-community-plugin</artifactId>
                <version>1.2.1</version>
                <configuration>
                    <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
                    <enableMultiModule>true</enableMultiModule>
                    <reportFormats>HTML,JSON</reportFormats>
                </configuration>
            </plugin>
        </plugins>
    </pluginManagement>

    <plugins>
        <plugin>
            <groupId>io.github.dodogeny</groupId>
            <artifactId>bastion-maven-community-plugin</artifactId>
            <executions>
                <execution>
                    <goals>
                        <goal>scan</goal>
                    </goals>
                    <phase>verify</phase>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

**Usage:**
```bash
# Scan all modules from parent
mvn clean verify
```

---

## ⚙️ Configuration Options

### Essential Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `nvdApiKey` | - | Your NVD API key (recommended) |
| `autoUpdate` | `true` | Auto-update vulnerability database |
| `failOnError` | `true` | Fail build on vulnerabilities |
| `severityThreshold` | `MEDIUM` | Minimum severity to report (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |

### Report Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `reportFormats` | `HTML,JSON` | Report formats (comma-separated) |
| `outputDirectory` | `target/bastion-reports` | Report output directory |

### Performance Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `scannerTimeout` | `900000` | Scan timeout in milliseconds (15 min) |
| `useOwaspPlugin` | `true` | Use OWASP Dependency-Check (recommended) |

---

## 🎯 Usage Examples

### Example 1: Fail Build on Critical/High Vulnerabilities

```xml
<configuration>
    <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
    <failOnError>true</failOnError>
    <severityThreshold>HIGH</severityThreshold>
</configuration>
```

### Example 2: Fast Offline Scanning (No Updates)

```bash
mvn bastion-maven-community-plugin:scan \
  -Dbastion.autoUpdate=false \
  -Dbastion.nvd.apiKey=YOUR_API_KEY
```

### Example 3: Custom Report Location

```xml
<configuration>
    <outputDirectory>${project.basedir}/security-reports</outputDirectory>
    <reportFormats>HTML,JSON</reportFormats>
</configuration>
```

### Example 4: IDE Integration (IntelliJ IDEA)

**Option A: Via POM Configuration (Recommended)**
1. Add plugin to `pom.xml` with `<phase>verify</phase>`
2. Run Maven goal: `clean verify`

**Option B: Direct Plugin Goal**
1. Add plugin to `pom.xml` (no execution block needed)
2. Run Maven goal: `io.github.dodogeny:bastion-maven-community-plugin:1.2.1:scan -Dbastion.nvd.apiKey=YOUR_API_KEY`

**Option C: Maven Run Configuration**
1. Create new Maven run configuration
2. Command: `verify` (uses POM config) or `bastion-maven-community-plugin:scan` (direct)
3. Add environment variable: `NVD_API_KEY=your-api-key`

---

## 🔧 Command Line Reference

### Basic Commands

```bash
# Run scan with API key
mvn bastion-maven-community-plugin:scan -Dbastion.nvd.apiKey=YOUR_KEY

# Run scan without updates (faster, uses cache)
mvn bastion-maven-community-plugin:scan -Dbastion.autoUpdate=false

# Run scan with specific severity threshold
mvn bastion-maven-community-plugin:scan -Dbastion.severityThreshold=HIGH

# Run as part of build lifecycle
mvn clean verify
```

### Advanced Commands

```bash
# Scan with custom timeout (30 minutes)
mvn bastion-maven-community-plugin:scan \
  -Dbastion.scannerTimeout=1800000 \
  -Dbastion.nvd.apiKey=YOUR_KEY

# Generate only HTML report
mvn bastion-maven-community-plugin:scan \
  -Dbastion.reportFormats=HTML

# Scan without failing build
mvn bastion-maven-community-plugin:scan \
  -Dbastion.failOnError=false
```

---

## 🐛 Troubleshooting

### Issue: "No vulnerabilities found" but dependencies are vulnerable

**Solution:** Ensure you're using the correct version:
```bash
# Check installed version
mvn io.github.dodogeny:bastion-maven-community-plugin:1.2.1:help

# Force update
mvn clean install -U
```

### Issue: Slow initial scan

**Cause:** First-time NVD database download (~300,000 CVEs)

**Solution:**
- Use NVD API key (faster downloads)
- Subsequent scans use cached database (much faster)
- Typical first scan: 5-10 minutes
- Subsequent scans: 30-60 seconds

### Issue: "Connection timeout" or "API rate limit"

**Solution:** Get an NVD API key:
```xml
<configuration>
    <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
</configuration>
```

### Issue: Build fails unexpectedly

**Solution:** Disable fail-on-error temporarily:
```bash
mvn verify -Dbastion.failOnError=false
```

---

## 📊 Understanding Results

### Severity Levels

- **🔴 CRITICAL** (9.0-10.0): Immediate action required
- **🟠 HIGH** (7.0-8.9): Fix as soon as possible
- **🟡 MEDIUM** (4.0-6.9): Plan to fix in next sprint
- **🟢 LOW** (0.1-3.9): Fix when convenient

### Report Sections

1. **Executive Summary**: Overview of vulnerabilities found
2. **Dependency Analysis**: All scanned dependencies
3. **Vulnerability Details**: CVE information, CVSS scores, remediation
4. **Statistics**: Performance metrics, JAR analysis

---

## ✅ Best Practices

1. **Use NVD API Key**: Faster downloads, no rate limiting
2. **Run in CI/CD**: Automate security scanning
3. **Set Severity Threshold**: `HIGH` for production, `MEDIUM` for development
4. **Cache NVD Database**: Reuse across builds
5. **Review Reports Regularly**: Weekly security reviews
6. **Update Dependencies**: Keep dependencies current

---

## 🚀 Next Steps

- Review generated reports in `target/bastion-reports/`
- Fix critical and high severity vulnerabilities
- Integrate into CI/CD pipeline
- Schedule regular security scans
- Consider upgrading to Enterprise Edition for advanced features

---

## 📚 Additional Resources

- **Support Email**: it.dodogeny@gmail.com
- **Full Documentation**: See `README.md`
- **GitHub Issues**: https://github.com/dodogeny/bastion-maven-plugin-community/issues
- **NVD API Key**: https://nvd.nist.gov/developers/request-an-api-key
- **OWASP Dependency-Check**: https://jeremylong.github.io/DependencyCheck/

---

## Version Information

- **Plugin Version**: 1.2.1
- **OWASP Dependency-Check**: 12.1.3
- **Java Version**: 11+ (21 recommended)
- **Maven Version**: 3.6.0+
