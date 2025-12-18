# Changelog

All notable changes to the Bastion Maven Plugin Community will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.5] - Current Release

### Added
- **🔄 Dynamic Version Management System**: Revolutionary approach to version management
  - Single source of truth in parent POM `<revision>` property
  - Maven resource filtering automatically replaces `1.2.5` in documentation
  - Eliminates manual version updates across README, QUICKSTART, and examples
  - Filtered documentation generated in `target/filtered-docs/` during build
  - New `VERSIONING.md` guide with complete documentation

- **📝 Enhanced Release Workflow**: Improved GitHub Actions release pipeline
  - Automatic version extraction from POM `<revision>` property
  - Intelligent version determination (auto-increment with POM fallback)
  - Comprehensive release notes generation with git commit changelog
  - Automatic comparison links to previous releases
  - Build verification with POM structure checks
  - Cache clearing for dodogeny artifacts

### Changed
- **📚 Documentation Updates**: All version references now dynamic
  - `README.md`: All plugin version examples use `1.2.5`
  - `QUICKSTART.md`: All configuration examples use `1.2.5`
  - `CHANGELOG.md`: Version history table includes current version dynamically
  - Compatibility matrix shows current version status

### Improved
- **🚀 Release Efficiency**: Streamlined release process
  - Single-point version update (only edit `<revision>` in parent POM)
  - Zero risk of missed version references
  - Automatic consistency across all documentation
  - CI/CD automatically extracts and uses correct version
  - Professional release notes with detailed changelogs

### Developer Experience
- **📖 New Documentation**: `VERSIONING.md` comprehensive guide
  - How the dynamic versioning system works
  - Maven resource filtering configuration details
  - Release process walkthrough
  - CI/CD integration explanation
  - Troubleshooting guide
  - Migration guide for adding new files
  - Best practices

## [1.2.0] - 2025-12-08

### Added
- **📦 Enhanced JAR-Level Vulnerability Analysis**: Comprehensive tracking of vulnerable JAR dependencies across scans
  - **✅ Resolved JARs**: Detailed tracking of JARs that are no longer vulnerable, including all fixed CVEs with severity levels
  - **🆕 New Vulnerable JARs**: Identification of newly introduced vulnerable dependencies with complete CVE details
  - **⏳ Pending Vulnerable JARs**: Enhanced tracking of ongoing vulnerable JARs with partial resolution detection
    - Tracks which CVEs were fixed within pending JARs
    - Identifies new CVEs discovered in previously vulnerable JARs
    - Shows severity breakdown (Critical, High, Medium, Low) for each JAR

- **📊 Improved Console Logging**: Enhanced console output for JAR analysis
  - Detailed breakdown of resolved, new, and pending vulnerable JARs
  - Total CVE counts per category (resolved, new, pending)
  - Top vulnerable JARs sorted by severity (prioritizing Critical, then High)
  - Severity distribution across all vulnerable JARs
  - Trend analysis with actionable insights

- **💾 Enhanced In-Memory Analysis**: Better trend analysis for in-memory database mode
  - Detailed vulnerability trend interpretation
  - Severity breakdown for currently vulnerable JARs
  - Top vulnerable JARs display (up to 5) sorted by criticality
  - Comprehensive trend messages based on dependency and vulnerability changes
  - Smart analysis of dependency addition/removal impacts

- **🧪 Comprehensive Test Coverage**: New test suites for enhanced functionality
  - `EnhancedJarAnalysisTest`: Tests for resolved, new, and pending JAR tracking
  - `EnhancedInMemoryJarAnalysisTest`: Tests for in-memory database JAR analysis
  - Tests for partial CVE resolution within pending JARs
  - Tests for complex multi-JAR scenarios
  - Tests for enhanced logging and reporting
  - 100% test coverage for new JAR analysis features

### Enhanced
- **📈 Trend Analysis Reports**: The HTML trend reports now include more detailed JAR dependency information
  - Resolved JARs section shows all fixed CVEs with their IDs and severity levels
  - New vulnerable JARs section displays all detected CVEs with severity breakdown
  - Pending vulnerable JARs section shows ongoing vulnerabilities with detailed CVE lists
  - Interactive charts and visualizations for better trend understanding
  - Visual indicators for dependency state changes

- **🔍 JAR Analysis Algorithm**: Improved accuracy in tracking dependency state changes
  - Better detection of version upgrades that resolve vulnerabilities
  - Accurate tracking of CVEs resolved within still-vulnerable dependencies
  - Enhanced comparison logic for identifying new vs ongoing vulnerabilities
  - Handles complex scenarios with mixed resolution states

- **📝 Detailed Console Output**: Enhanced visibility into JAR-level changes
  - Formatted output boxes for better readability
  - Clear categorization of JAR states (resolved/new/pending)
  - Individual JAR details with version and CVE information
  - Summary statistics for quick assessment

### Technical Details
- **Version**: Bumped to 1.2.0
- **Core Changes**:
  - Enhanced `generateJarAnalysis()` method with detailed CVE tracking
  - Enhanced `generateInMemoryJarAnalysis()` method with better trend analysis
  - Improved logging with formatted output boxes and better readability
  - Added comprehensive assertions in test suites
- **Test Coverage**: 14 new test cases across 2 new test classes
- **Backward Compatibility**: Fully compatible with version 1.1.x configurations

### Documentation
- **CHANGELOG.md**: Created comprehensive version history with detailed change tracking
- **Test Documentation**: Inline documentation for all new test cases
- **Code Comments**: Enhanced comments explaining JAR analysis algorithms

### Upgrade Guide
```xml
<!-- Update your pom.xml -->
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-parent</artifactId>
    <version>1.2.0</version>
</plugin>
```

No configuration changes required. The enhanced JAR analysis will automatically be available in your next scan.

### Benefits of Upgrading to 1.2.0
1. **Better Visibility**: See exactly which JARs had vulnerabilities fixed
2. **Improved Prioritization**: Enhanced severity breakdown helps focus on critical issues first
3. **Partial Progress Tracking**: Know when some CVEs in a JAR are fixed even if others remain
4. **Enhanced Reports**: Trend reports now show detailed dependency-level changes
5. **Better Logging**: Console output provides actionable insights about vulnerability trends

---

## [1.1.1] - 2025-11-08

### Added
- **🎉 Zero-Configuration NVD Database Setup**: Complete automation of database initialization
  - Automatic detection and initialization of NVD database on first run
  - No manual `mvn dependency-check:update-only` commands required
  - Intelligent pre-flight checks before OWASP plugin invocation
  - Clear, actionable error messages with solution options
- **🔄 Intelligent Auto-Update System**: Always-on CVE data synchronization
  - Auto-update permanently enabled by default for latest vulnerability data
  - Removed `bastion.autoUpdate` parameter (always true now)
  - OWASP Dependency-Check intelligently determines when updates are needed
  - Smart incremental updates - downloads only new CVE data, not entire database
  - Database age tracking and logging for transparency

### Improved
- **⚡ First-Time User Experience**: Eliminated manual setup complexity
  - Automatic full NVD database download on first scan (~317,000 CVEs, 20-30 min with API key)
  - Subsequent scans only download new CVE data (typically seconds to minutes)
  - Informative progress messages during database initialization
  - Clear distinction between first-time setup and incremental updates
- **📊 Enhanced Logging**: Better visibility into database status
  - Database age display (e.g., "age: 2 days")
  - NVD API key usage warnings and recommendations
  - Auto-update confirmation messages
  - First-time setup progress indicators
- **🚀 OWASP Dependency-Check 12.1.3**: Updated to latest version
  - Improved vulnerability detection accuracy
  - Better NVD API 2.0 integration
  - Enhanced performance and stability

### Changed
- **Breaking**: Java 21+ now required (upgraded from Java 11+)
- **Breaking**: Removed `bastion.autoUpdate` parameter - always enabled
- **Breaking**: Removed `bastion.nvd.updateThresholdDays` parameter - OWASP handles update logic
- Database location changed to: `~/.m2/repository/org/owasp/dependency-check-utils/12.1.3/data/`

### Technical
- Added `isNvdDatabaseInitialized()` method for database existence checking
- Added `getNvdDatabasePath()` method for multi-location database detection
- Added `initializeNvdDatabase()` method for programmatic database initialization
- Modified `performHybridScan()` with defensive pre-flight database checks
- Updated `invokeOwaspPlugin()` to always pass `-DautoUpdate=true` to OWASP

## [1.1.0] - 2025-08-29

### Added
- **🚀 Smart NVD Database Caching**: Revolutionary performance improvement system
  - Intelligent remote change detection via HTTP HEAD requests to NVD servers
  - Configurable cache validity periods (default 6 hours)
  - 5-10x faster scan times when database hasn't changed (8-13min → 2-3min)
  - Different caching strategies for users with/without NVD API keys
  - Automatic cache metadata management with robust fallback mechanisms
  - Custom cache directory configuration support
  - Smart caching can be enabled/disabled per scan
- **🔧 Enhanced Scanner Configuration**: Extended configuration options
  - `smartCachingEnabled`: Toggle smart caching feature
  - `cacheValidityHours`: Customize cache check frequency
  - `cacheDirectory`: Specify custom cache storage location
  - Backward compatible with existing configurations

### Improved
- **⚡ Performance Optimization**: Massive scan time improvements
  - First scan downloads and caches NVD database (~500MB)
  - Subsequent scans check remote database changes before downloading
  - With NVD API key: More frequent and accurate cache validation
  - Without API key: Conservative 24-hour cache policy for reliability
- **🔍 Enhanced Logging**: Better visibility into caching decisions
  - Clear cache status messages with emojis for easy identification
  - Detailed logging of cache hit/miss decisions
  - Performance impact metrics and timing information
- **📁 Default Cache Location**: Sensible defaults for cache storage
  - Linux/Mac: `~/.bastion/nvd-cache/`
  - Windows: `%USERPROFILE%\.bastion\nvd-cache\`
  - Automatic cache directory creation and management

### Technical
- **🏗️ New Classes**: Added `NvdCacheManager` for intelligent caching
- **🧪 Comprehensive Testing**: Complete test coverage for caching functionality
- **📚 Documentation**: Detailed caching guide and usage examples
- **🔄 Integration**: Seamless integration with existing OWASP scanner infrastructure

## [Unreleased]

### Added
- **🌳 Graphical Dependency Tree Visualization**: Interactive dependency hierarchy display
  - ASCII-based tree structure similar to `mvn dependency:tree`
  - Color-coded vulnerability indicators with severity badges
  - Direct vs Transitive dependency classification
  - Risk assessment and remediation guidance
  - Local Maven repository file path display
  - Clean dependency context for comprehensive view
- **📋 Enhanced CVE Documentation Tables**: Comprehensive vulnerability details
  - Full CVE descriptions with clickable official links
  - MITRE CVE database and NVD integration
  - Limited additional references (max 3) to prevent clutter
  - Color-coded severity badges and CVSS scores
  - Affected component and version information
- **💾 Community Edition In-Memory Database**: Fast session-based storage
  - Zero-configuration in-memory vulnerability database
  - Session-based storage with automatic 24-hour cleanup
  - Memory optimization with configurable limits (50 projects, 10 sessions/project)
  - JSON export/import capabilities for session persistence
  - Thread-safe concurrent access with automatic memory management
- **🔐 Enhanced Licensing Architecture**: Commercial vs Community feature separation
  - H2 persistent database moved to Commercial Edition
  - In-memory database for Community Edition
  - Historical trend analysis as commercial feature
  - JSON report generation remains free for Community Edition
  - Updated LemonSqueezy licensing integration
- **JSON File Storage**: Complete alternative to database storage
  - File-based vulnerability tracking with historical data
  - Zero configuration - just specify a file path
  - Version control friendly for audit trails
  - Portable and human-readable format
  - Full trend analysis support from JSON data
- **Integrated Data Purge Management**: Comprehensive data lifecycle tools
  - Merged `BastionPurgeMojo` functionality into `BastionScanMojo`
  - Support for both database and JSON file purge operations
  - Interactive confirmation with impact analysis
  - Dry run mode for safe operation preview
  - Project-specific and time-based purge options
  - Force and auto-confirm modes for automation
- **Enhanced Trend Analysis**: Advanced vulnerability tracking
  - Compare current scan with historical results
  - Directional trend indicators (⬆️⬇️➡️) for all severity levels
  - Display previous scan date and total historical scans
  - Works with both database and JSON file storage
- **Comprehensive Developer Documentation**: 
  - Complete developer guide with architecture overview

### Enhanced
- **📊 Report Generation**: Multi-format reports with advanced visualizations
  - HTML reports now include interactive dependency trees
  - JSON reports include detailed CVE descriptions
  - CSV reports enhanced with documentation links
  - PDF and SARIF reports available for Commercial Edition
- **⚡ Performance Optimizations**: Memory and resource usage improvements
  - In-memory database with automatic cleanup
  - Configurable session limits and TTL
  - Efficient memory management for large projects
  - Thread-safe operations for concurrent access

### Fixed
- **🐛 FreeMarker Template Issues**: Resolved boolean expression errors
  - Fixed `isDirect` method evaluation in dependency tree display
  - Proper handling of boolean properties in FreeMarker templates
  - Enhanced error handling for template processing
- **🔧 Scanner Configuration**: Improved OWASP integration
  - Fixed `ANALYZER_FILENAME_ENABLED` to `ANALYZER_FILE_NAME_ENABLED`
  - Enhanced ZIP file exclusion for JAR-only scanning
  - Improved error handling and logging

### Changed
- **🏗️ Architecture Updates**: Separation of Community vs Commercial features
  - H2 database is now Commercial Edition only
  - Community Edition uses fast in-memory database
  - Enhanced licensing validation and feature control
  - Updated documentation to reflect new architecture
  - Code examples and implementation patterns
  - Testing strategies and debugging information
  - Contribution guidelines and development setup

### Changed
- **Storage Architecture**: Refactored to support multiple backends
  - Added storage validation to prevent conflicting configurations
  - Database options automatically disabled when JSON storage is enabled
  - Improved error handling and user feedback
- **Plugin Goal Consolidation**: Simplified command interface  
  - Removed separate `purge` goal - now integrated into `scan` goal
  - All operations accessible through unified `bastion:scan` command
  - Backward compatible with existing configurations

### Configuration Parameters Added
- `bastion.storage.useJsonFile` - Enable JSON file storage (default: false)
- `bastion.storage.jsonFilePath` - Path to JSON storage file  
- `bastion.purgeBeforeScan` - Purge data before scanning (default: false)
- `bastion.purge.force` - Skip interactive confirmation (default: false)
- `bastion.purge.confirm` - Auto-confirm purge operations (default: false) 
- `bastion.purge.projectOnly` - Purge only current project data (default: false)
- `bastion.purge.olderThanDays` - Purge records older than X days (default: 0)
- `bastion.purge.dryRun` - Preview purge operations without executing (default: false)

### Fixed
- **Type Casting Error**: Fixed boolean to int casting in JSON purge operations
- **Storage Initialization**: Improved error handling during storage setup
- **Maven Parameter Validation**: Better validation of configuration parameters

### Documentation Updates
- Updated README.md with comprehensive JSON storage and purge documentation
- Enhanced installation guide with new configuration examples
- Updated documentation index with new features
- Added complete developer guide for contributors

### Examples Added
```bash
# JSON storage with trend analysis
mvn bastion:scan -Dbastion.storage.useJsonFile=true

# Purge old data before scanning  
mvn bastion:scan -Dbastion.purgeBeforeScan=true -Dbastion.purge.olderThanDays=30

# Safe purge preview
mvn bastion:scan -Dbastion.purgeBeforeScan=true -Dbastion.purge.dryRun=true

# Project-specific JSON cleanup
mvn bastion:scan \
  -Dbastion.storage.useJsonFile=true \
  -Dbastion.purgeBeforeScan=true \
  -Dbastion.purge.projectOnly=true
```

## [1.0.0] - 2024-01-15

### Added
- Initial release of Bastion Maven Plugin Enterprise
- Multi-module Maven architecture
- OWASP Dependency-Check integration
- Database storage (H2, PostgreSQL, MySQL)
- Multi-format reporting (HTML, JSON, CSV, PDF, SARIF)
- Enterprise licensing system with LemonSqueezy integration
- Email notification system (Commercial Edition)
- Real-time monitoring capabilities (Commercial Edition)
- Basic SIEM integration framework (Commercial Edition)
- Comprehensive scan statistics and performance metrics
- OWASP Dependency-Check integration
- GitHub Security Advisory integration

### Features
- **Open Source Edition**:
  - OWASP Dependency-Check scanner
  - Basic HTML/JSON reports  
  - Local H2 database support
  - Basic performance metrics
  - Multi-module project scanning

- **Commercial Edition**:
  - Enhanced GitHub Security Advisory integration
  - Advanced email notifications with SMTP support
  - Enterprise database support (PostgreSQL, MySQL)
  - Premium report formats (PDF, SARIF)
  - Real-time monitoring capabilities
  - Priority enterprise support

### Technical Implementation  
- Maven plugin architecture with thread-safe execution
- Asynchronous scanning with CompletableFuture
- Comprehensive database schema with Flyway migrations
- Jackson-based JSON processing
- SLF4J logging integration
- Extensive configuration parameter support
- Enterprise-grade license validation system

---

## Version History

| Version | Release Date | Key Features | Status |
|---------|-------------|--------------|--------|
| 1.2.5 | Current | Enhanced JAR analysis, dynamic versioning, improved release workflow | **Recommended** |
| 1.2.0   | 2025-12-08  | Enhanced JAR analysis, improved logging, comprehensive test coverage | Stable |
| 1.1.1   | 2025-11-08  | Zero-config NVD database, intelligent auto-update, Java 21+ | Stable |
| 1.1.0   | 2025-08-29  | Smart NVD caching, performance optimization | Stable |
| 1.0.0   | 2024-01-15  | Initial release with core scanning and reporting | Legacy |

---

For detailed information about any version, see the [releases page](https://github.com/jdneemuth/bastion-maven-plugin-enterprise/releases).

For upgrade instructions, see the [Migration Guide](MIGRATION.md).
