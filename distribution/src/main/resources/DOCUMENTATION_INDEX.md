# SecHive Maven Plugin - Documentation Index

This documentation package contains comprehensive information about SecHive Maven Plugin v${project.version}.

## 📚 Documentation Structure

### Quick Start
- **[README.md](../../../README.md)** - Project overview and feature summary (located at project root)
- **[INSTALLATION.md](INSTALLATION.md)** - Complete installation guide
- **[QUICKSTART.md](docs/QUICKSTART.md)** - 5-minute getting started guide
- **[CHANGELOG.md](docs/CHANGELOG.md)** - Version history and release notes

### Developer Documentation
- **[DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)** - Development setup and contribution guide
- **[VERSIONING.md](docs/VERSIONING.md)** - Version management and release process

### Workflow Documentation
- **[RELEASE_WORKFLOW.md](docs/RELEASE_WORKFLOW.md)** - Release workflow and CI/CD setup
- **[EMAIL_NOTIFICATIONS_SETUP.md](docs/EMAIL_NOTIFICATIONS_SETUP.md)** - Email notification configuration

### License & Compliance
- **[LICENSE](../../../LICENSE)** - Apache License 2.0 (located at project root)
- **[LICENSE_COMPLIANCE_GUIDE.md](docs/LICENSE_COMPLIANCE_GUIDE.md)** - License compliance guide for enterprise

### Technical Documentation
- **[API Documentation](api/)** - Complete JavaDoc API reference
- **[Site Documentation](site/)** - Generated Maven site with reports

### Module Documentation
- **[vulnerability-db/](modules/vulnerability-db/)** - Database layer documentation
- **[scanner-core/](modules/scanner-core/)** - Scanning engine documentation
- **[reporting/](modules/reporting/)** - Report generation documentation
- **[plugin/](modules/plugin/)** - Maven plugin documentation

### Configuration & Examples
- **[examples/](examples/)** - Real-world usage examples and templates
- **[schemas/](schemas/)** - Configuration schema definitions

## 🎯 Quick Navigation by Role

### 👨‍💼 For Decision Makers
1. [README.md](../../../README.md) - Feature overview and competitive advantages
2. [CHANGELOG.md](docs/CHANGELOG.md) - Version history and what's new

### 👨‍💻 For Developers
1. [QUICKSTART.md](docs/QUICKSTART.md) - Get running in 5 minutes
2. [DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) - Development setup and contribution guide
3. [VERSIONING.md](docs/VERSIONING.md) - Version management strategy
4. [RELEASE_WORKFLOW.md](docs/RELEASE_WORKFLOW.md) - Release process and automation

### 🛡️ For Security Teams
1. [README.md](../../../README.md) - Security scanning capabilities and features
2. [LICENSE_COMPLIANCE_GUIDE.md](docs/LICENSE_COMPLIANCE_GUIDE.md) - License compliance management

### 🔧 For Operations Teams
1. [INSTALLATION.md](INSTALLATION.md) - Deployment and installation
2. [QUICKSTART.md](docs/QUICKSTART.md) - Quick configuration guide
3. [EMAIL_NOTIFICATIONS_SETUP.md](docs/EMAIL_NOTIFICATIONS_SETUP.md) - Email notification configuration

## 📊 Report Types

### Standard Reports (Open Source)
- **HTML Reports** - Human-readable vulnerability reports with trend analysis
- **JSON Reports** - Machine-readable data for automation
- **CSV Reports** - Spreadsheet-compatible exports
- **JSON File Storage** - File-based vulnerability tracking with historical trends

### Premium Reports (Commercial Edition)
- **PDF Reports** - Executive-ready presentations
- **SARIF Reports** - Security Analysis Results Interchange Format
- **Excel Reports** - Advanced spreadsheets with pivot tables

## 🏗️ Architecture Overview

SecHive is designed as a multi-module Maven project:

```
sechive-maven-plugin/
├── vulnerability-db/     # Database layer (H2/PostgreSQL/MySQL)
├── scanner-core/         # Multi-source vulnerability scanning
├── reporting/           # Multi-format report generation
├── plugin/              # Maven plugin implementation
├── enterprise/          # Commercial features and licensing
└── distribution/        # Packaging and distribution
```

## 🆓 vs 💼 Edition Comparison

| Feature | Open Source | Commercial |
|---------|-------------|------------|
| **Vulnerability Scanning** | ✅ OWASP Dependency-Check | ✅ + Snyk, Enhanced GitHub |
| **Reporting** | ✅ HTML, JSON, CSV | ✅ + PDF, SARIF, Excel |
| **Storage Options** | ✅ H2 + JSON File | ✅ + PostgreSQL, MySQL |
| **Trend Analysis** | ✅ JSON File Based | ✅ Database + Advanced Analytics |
| **Data Management** | ✅ Purge Operations | ✅ Advanced Data Lifecycle |
| **Email Notifications** | ❌ | ✅ SMTP + Templates |
| **SIEM Integration** | ❌ | ✅ Splunk, Elastic, etc. |
| **Real-time Monitoring** | ❌ | ✅ WebSocket alerts |
| **Support** | Community | Priority Support |

## 🚀 Getting Started

### 1. Choose Your Installation Method
- **Maven Repository** (recommended): Add plugin to your `pom.xml`
- **Direct Download**: Download and extract distribution package
- **Build from Source**: Clone repository and build locally

### 2. Run Your First Scan
```bash
mvn mu.dodogeny:sechive-maven-plugin:${project.version}:scan
```

### 3. Review Results
Check `target/sechive-reports/` for generated security reports.

### 4. Configure for Your Needs
- **Basic Setup**: [examples/basic-setup/](examples/basic-setup/)
- **Enterprise Setup**: [examples/enterprise-setup/](examples/enterprise-setup/)
- **CI/CD Integration**: [examples/ci-cd/](examples/ci-cd/)

## 📞 Support & Resources

### Community Support (Open Source)
- **Email**: it.dodogeny@gmail.com
- **GitHub Issues**: [https://github.com/dodogeny/sechive-maven-plugin/issues](https://github.com/dodogeny/sechive-maven-plugin/issues)
- **Stack Overflow**: Use tag `sechive-maven-plugin`
- **Documentation**: [https://dodogeny.github.io/sechive-maven-plugin](https://dodogeny.github.io/sechive-maven-plugin)

### Enterprise Support (Commercial)
- **Email**: it.dodogeny@gmail.com
- **Priority Queue**: Guaranteed response within business hours
- **Professional Services**: Custom integrations and training
- **Phone Support**: Available with Premium plans

### Additional Resources
- **Official Website**: [https://github.com/dodogeny/sechive-maven-plugin](https://github.com/dodogeny/sechive-maven-plugin)
- **Blog & Tutorials**: [https://dodogeny.github.io/sechive-maven-plugin](https://dodogeny.github.io/sechive-maven-plugin)
- **Commercial Licensing**: [https://github.com/dodogeny/sechive-maven-plugin/pricing](https://github.com/dodogeny/sechive-maven-plugin/pricing)

## 🔄 Version Information

- **Plugin Version**: ${project.version}
- **Build Date**: ${maven.build.timestamp}
- **Minimum Java**: JDK 8+
- **Minimum Maven**: 3.6.0+

## 📜 License Information

### Open Source Edition
- **License**: Apache License 2.0
- **Source Code**: Available on GitHub
- **Usage**: Unlimited for open source and commercial projects

### Commercial Edition  
- **License**: Proprietary License
- **Pricing**: One-time fee per organization
- **Features**: Premium scanning, reporting, and support
- **Purchase**: [https://github.com/dodogeny/sechive-maven-plugin/](https://github.com/dodogeny/sechive-maven-plugin/pricing)

---

**Thank you for choosing SecHive Maven Plugin!**

*Your enterprise fortress against security vulnerabilities*  
*Developed with ❤️ by [Dodogeny](https://dodogeny.mu) in Mauritius 🇲🇺*