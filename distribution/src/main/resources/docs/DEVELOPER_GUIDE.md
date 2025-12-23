# Bastion Maven Plugin - Developer Guide

This guide provides comprehensive information for developers working on the Bastion Maven Plugin codebase.

## 🏗️ Project Architecture

### Multi-Module Structure

```
bastion-maven-plugin/
├── vulnerability-db/         # Database layer and data models
│   ├── src/main/java/mu/dodogeny/security/
│   │   ├── database/        # VulnerabilityDatabase implementation
│   │   └── model/           # ScanResult, Vulnerability entities
│   └── src/main/resources/db/migration/  # Flyway SQL migrations
├── scanner-core/            # Vulnerability scanning engine
│   └── src/main/java/io/github/dodogeny/security/scanner/
│       ├── VulnerabilityScanner.java        # Scanner interface
│       ├── OwaspDependencyCheckScanner.java # OWASP implementation
│       └── NvdCacheManager.java             # Smart NVD caching (v1.1.0+)
├── reporting/               # Report generation system
│   ├── src/main/java/mu/dodogeny/security/report/
│   │   └── ReportGenerator.java             # Multi-format reporting
│   └── src/main/resources/templates/       # Report templates
├── plugin/                  # Maven plugin implementation
│   └── src/main/java/mu/dodogeny/security/plugin/
│       └── BastionScanMojo.java             # Main plugin logic
├── enterprise/              # Commercial features
│   └── src/main/java/mu/dodogeny/security/
│       ├── licensing/       # License validation
│       ├── notifications/   # Email notifications
│       ├── siem/           # SIEM integrations
│       └── intelligence/   # Threat intelligence
└── distribution/            # Packaging and distribution
    └── src/main/           # Documentation and examples
```

## 🔧 Development Environment Setup

### Prerequisites

- **Java**: JDK 11+ (recommended for development, supports JDK 8 runtime)
- **Maven**: 3.8.0 or higher
- **IDE**: IntelliJ IDEA or Eclipse with Maven support
- **Git**: For version control

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/dodogeny/bastion-maven-plugin.git
cd bastion-maven-plugin

# Install dependencies and build all modules
mvn clean install

# Run tests
mvn test

# Run integration tests
mvn integration-test

# Generate project reports
mvn site
```

### IDE Configuration

#### IntelliJ IDEA

1. Import as Maven project
2. Enable annotation processing for Maven plugins
3. Configure Code Style:
   - Indent: 4 spaces
   - Line length: 100 characters
   - Import organization: java.*, javax.*, *, static *

#### Eclipse

1. Import → Existing Maven Projects
2. Enable Project Facets for Maven
3. Install m2e connector for Maven plugin development

## 📝 Code Structure and Patterns

### Maven Plugin Development

The main plugin implementation is in `BastionScanMojo.java`:

```java
@Mojo(name = "scan", 
      defaultPhase = LifecyclePhase.VERIFY,
      requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
      threadSafe = true)
public class BastionScanMojo extends AbstractMojo {
    
    // Plugin parameters with @Parameter annotations
    @Parameter(property = "bastion.storage.useJsonFile", defaultValue = "false")
    private boolean useJsonFileStorage;
    
    // Main execution method
    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        // Implementation logic
    }
}
```

### Storage Abstraction

The plugin supports multiple storage backends:

#### Database Storage (Traditional)
```java
// Initialize database connection
VulnerabilityDatabase database = new VulnerabilityDatabase(config, logger);
database.storeScanResultBatch(scanResult);
```

#### JSON File Storage (New)
```java
// JSON file storage with trend analysis
JsonVulnerabilityStore store = loadExistingJsonData();
JsonScanEntry entry = new JsonScanEntry();
entry.setTimestamp(LocalDateTime.now());
entry.setScanResult(result);
store.getScanHistory().add(entry);
```

### Data Purge System

Unified purge functionality for both storage types:

```java
private void performPurge() throws SQLException {
    if (useJsonFileStorage) {
        performJsonPurge();  // JSON file operations
    } else {
        performActualPurge(); // Database operations
    }
}
```

## 🔄 Key Components

### 1. Vulnerability Scanning (`scanner-core`)

```java
public interface VulnerabilityScanner {
    CompletableFuture<ScanResult> scanProject(String projectPath);
    String getName();
    void configure(ScannerConfiguration config);
}
```

**Implementation Notes:**
- Asynchronous scanning with `CompletableFuture`
- Configurable timeout and caching
- Support for multiple vulnerability databases

### 2. Database Layer (`vulnerability-db`)

```java
public class VulnerabilityDatabase {
    // Store scan results with batch operations
    public void storeScanResultBatch(ScanResult result);
    
    // Purge operations for data lifecycle management
    public int deleteAllVulnerabilities();
    public int deleteScanResultsForProject(String groupId, String artifactId);
    public int deleteScanResultsOlderThan(int days);
}
```

**Database Schema:**
- `scan_results`: Main scan metadata
- `vulnerabilities`: Individual CVE details  
- `scan_statistics`: Performance metrics
- `performance_metrics`: Detailed timing data

### 3. Report Generation (`reporting`)

```java
public class ReportGenerator {
    public void generateReport(ScanResult result, 
                              ReportFormat format, 
                              String outputPath);
    
    // Supported formats
    public enum ReportFormat {
        HTML, JSON, CSV, SARIF, PDF
    }
}
```

### 4. JSON Storage System (New Feature)

**Data Structure:**
```java
public class JsonVulnerabilityStore {
    private LocalDateTime created;
    private LocalDateTime lastUpdated;
    private List<JsonScanEntry> scanHistory;
}

public class JsonScanEntry {
    private LocalDateTime timestamp;
    private ScanResult scanResult;
    private JsonProjectInfo projectInfo;
}
```

**Trend Analysis:**
- Compares current scan with previous scans
- Calculates vulnerability trends by severity
- Displays directional indicators (⬆️⬇️➡️)

## 🧪 Testing Strategy

### Unit Tests

```bash
# Run unit tests for specific module
mvn test -pl plugin

# Run with coverage
mvn test jacoco:report
```

### Integration Tests

```bash
# Run integration tests (slower, real Maven projects)
mvn integration-test

# Run specific integration test
mvn test -Dtest=BastionScanMojoIntegrationTest
```

### Test Data

Test projects are located in `src/test/resources/projects/`:
- `basic-project/`: Simple Maven project with known vulnerabilities
- `multi-module-project/`: Complex multi-module setup
- `json-storage-project/`: JSON storage testing scenarios

### Test Configuration Examples

```java
@Test
public void testJsonStorageIntegration() throws Exception {
    BastionScanMojo mojo = new BastionScanMojo();
    mojo.setUseJsonFileStorage(true);
    mojo.setJsonFilePath("/tmp/test-vulnerabilities.json");
    mojo.execute();
    
    // Verify JSON file creation and content
    assertTrue(Files.exists(Paths.get("/tmp/test-vulnerabilities.json")));
}

@Test  
public void testPurgeOperations() throws Exception {
    // Test dry run mode
    mojo.setPurgeBeforeScan(true);
    mojo.setDryRun(true);
    mojo.execute();
    
    // Verify no data was actually deleted
}
```

## 📊 Performance Considerations

### Memory Management

```java
// Large project optimization
VulnerabilityScanner.ScannerConfiguration config = 
    new VulnerabilityScanner.ScannerConfiguration();
config.setTimeoutMs(600000); // 10 minutes for large projects
config.setEnableCache(true);  // Cache CVE lookups
config.setBatchSize(50);      // Process dependencies in batches
```

### Concurrent Processing

```java
// Multi-module parallel scanning
if (enableMultiModule && isMultiModuleProject()) {
    CompletableFuture<ScanResult> scanFuture = 
        scanner.scanProject(session.getTopLevelProject().getBasedir().getAbsolutePath());
}
```

### JSON File Performance

- **Large files**: Consider pagination for very large scan histories
- **Parsing optimization**: Use streaming JSON for massive datasets
- **File locking**: Implement file locking for concurrent access

### Smart NVD Database Caching (v1.1.0+)

The smart caching system dramatically improves scan performance by avoiding unnecessary NVD database downloads:

```java
// Smart cache configuration
VulnerabilityScanner.ScannerConfiguration config = 
    new VulnerabilityScanner.ScannerConfiguration();
config.setAutoUpdate(true);
config.setSmartCachingEnabled(true);
config.setCacheValidityHours(6);  // Check every 6 hours
config.setCacheDirectory(System.getProperty("user.home") + "/.bastion/nvd-cache");
```

**Architecture:**

```java
// NvdCacheManager handles intelligent caching
public class NvdCacheManager {
    // Checks remote NVD database modification times
    public boolean isCacheValid(String apiKey) {
        // 1. Check cache metadata
        // 2. Query remote NVD servers (HTTP HEAD)
        // 3. Compare modification timestamps
        // 4. Return true if cache is current
    }
    
    // Updates cache metadata after successful downloads
    public void updateCacheMetadata() {
        // Store last check time and remote modification time
    }
}
```

**Performance Impact:**
- **First scan**: 8-13 minutes (downloads ~500MB NVD database)
- **Cached scans**: 2-3 minutes (skips download when no changes)
- **API key users**: More frequent and accurate cache checks
- **No API key**: Conservative 24-hour cache validity

## 🔐 Security Considerations

### Credential Management

```java
// Never log sensitive information
if (StringUtils.isNotBlank(apiKey)) {
    getLog().info("API key configured: " + apiKey.substring(0, 4) + "****");
}

// Use Maven settings encryption for credentials
String decryptedPassword = settingsDecrypter.decrypt(encryptedPassword);
```

### License Validation

```java
// Commercial license verification
LemonSqueezyLicenseManager licenseManager = new LemonSqueezyLicenseManager();
LicenseValidationResult result = licenseManager.validateLicense(apiKey);

if (result != null && result.isValid()) {
    enableCommercialFeatures();
} else {
    fallbackToOpenSourceMode();
}
```

## 🚀 Building and Releasing

### Local Build

```bash
# Full build with tests
mvn clean verify

# Skip tests for faster build  
mvn clean package -DskipTests

# Build specific module
mvn clean package -pl plugin -am
```

### Release Process

```bash
# Prepare release
mvn release:prepare -DdryRun=true

# Perform release
mvn release:prepare
mvn release:perform

# Deploy to Maven Central
mvn deploy -P release
```

### Distribution Packaging

```bash
# Create distribution archives
mvn clean package -P distribution

# Generated files:
# target/bastion-maven-plugin-${version}-bin.zip
# target/bastion-maven-plugin-${version}-bin-unix.tar.gz
```

## 📚 Adding New Features

### 1. Storage Backend Extension

To add a new storage backend (e.g., MongoDB):

```java
// 1. Create storage interface implementation
public class MongoVulnerabilityStorage implements VulnerabilityStorage {
    @Override
    public void storeResults(ScanResult result) { 
        // MongoDB storage logic
    }
    
    @Override
    public void purgeData(PurgeOptions options) {
        // MongoDB purge logic
    }
}

// 2. Update BastionScanMojo configuration
@Parameter(property = "bastion.storage.type", defaultValue = "h2")
private String storageType; // h2, postgresql, mysql, mongodb, json

// 3. Add factory method for storage creation
private VulnerabilityStorage createStorage() {
    switch (storageType) {
        case "mongodb": return new MongoVulnerabilityStorage(config);
        case "json": return new JsonFileStorage(jsonFilePath);
        default: return new DatabaseStorage(config);
    }
}
```

### 2. Report Format Extension

To add a new report format:

```java
// 1. Add enum value
public enum ReportFormat {
    HTML, JSON, CSV, SARIF, PDF, MARKDOWN // New format
}

// 2. Implement report generator
public class MarkdownReportGenerator implements ReportFormatGenerator {
    @Override
    public void generate(ScanResult result, String outputPath) {
        // Markdown generation logic
    }
}

// 3. Register in ReportGenerator factory
private ReportFormatGenerator createGenerator(ReportFormat format) {
    switch (format) {
        case MARKDOWN: return new MarkdownReportGenerator();
        // ... other formats
    }
}
```

### 3. Scanner Integration

To add a new vulnerability scanner:

```java
// 1. Implement VulnerabilityScanner interface
public class SnykScanner implements VulnerabilityScanner {
    @Override
    public CompletableFuture<ScanResult> scanProject(String projectPath) {
        return CompletableFuture.supplyAsync(() -> {
            // Snyk API integration
            return scanResult;
        });
    }
}

// 2. Register scanner in plugin configuration
@Parameter(property = "bastion.scanners", defaultValue = "owasp")
private List<String> enabledScanners;

// 3. Initialize and configure scanners
private VulnerabilityScanner initializeScanner() {
    VulnerabilityScanner scanner = new OwaspDependencyCheckScanner();
    VulnerabilityScanner.ScannerConfiguration config = 
        new VulnerabilityScanner.ScannerConfiguration();
    config.setTimeoutMs(scannerTimeout);
    config.setSeverityThreshold(severityThreshold);
    scanner.configure(config);
    return scanner;
}
```

## 🐛 Debugging and Troubleshooting

### Enable Debug Logging

```bash
# Maven debug mode
mvn bastion:scan -X

# Specific logger configuration
mvn bastion:scan -Dorg.slf4j.simpleLogger.log.io.github.dodogeny.security=DEBUG
```

### Common Development Issues

#### Plugin Not Found
```bash
# Ensure plugin is installed in local repository
mvn clean install -pl plugin
```

#### JSON Parsing Errors
```java
// Add error handling for JSON operations
try {
    JsonVulnerabilityStore store = jsonMapper.readValue(jsonFile, JsonVulnerabilityStore.class);
} catch (JsonProcessingException e) {
    getLog().warn("Failed to parse JSON file, creating new store: " + e.getMessage());
    return createNewStore();
}
```

#### Memory Issues
```bash
# Increase Maven memory for development
export MAVEN_OPTS="-Xmx4g -XX:MaxMetaspaceSize=1g"
```

## 📖 Documentation Updates

When adding new features, update:

1. **README.md**: Feature overview and usage examples
2. **INSTALLATION.md**: Configuration parameters
3. **DEVELOPER_GUIDE.md**: Implementation details
4. **JavaDoc**: Code documentation
5. **Integration Tests**: Test coverage for new features

### Documentation Standards

- Use clear, concise language
- Include code examples for all features
- Provide both XML configuration and command-line examples
- Add troubleshooting sections for complex features
- Update parameter reference tables

## 🤝 Contributing Guidelines

### Code Style

- Follow Oracle Java Code Conventions
- Use 4-space indentation
- Maximum line length: 100 characters
- Use meaningful variable and method names
- Add JavaDoc for public methods and classes

### Commit Messages

```
feat(storage): add MongoDB storage backend support

- Implement MongoVulnerabilityStorage class
- Add MongoDB configuration parameters  
- Update documentation with setup instructions
- Add integration tests for MongoDB operations

Closes #123
```

### Pull Request Process

1. Create feature branch from `develop`
2. Implement changes with tests
3. Update documentation
4. Submit PR with clear description
5. Address review feedback
6. Merge after approval

---

**Happy coding!** 🚀

*For questions or support, reach out to the development team at it.dodogeny@gmail.com*