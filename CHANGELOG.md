# Changelog

All notable changes to the Bastion Maven Plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Initial release of Bastion Maven Plugin
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

- **v1.0.0** (2024-01-15): Initial release with core scanning and reporting
- **v1.1.0** (Unreleased): JSON storage, integrated purge management, enhanced trends

---

For detailed information about any version, see the [releases page](https://github.com/jdneemuth/bastion-maven-plugin/releases).

For upgrade instructions, see the [Migration Guide](MIGRATION.md).
