# Bastion Maven Plugin - Documentation Index

This documentation package contains comprehensive information about Bastion Maven Plugin v${project.version}.

## 📚 Documentation Structure

### Quick Start
- **[README.md](README.md)** - Project overview and feature summary
- **[INSTALLATION.md](INSTALLATION.md)** - Complete installation guide
- **[QUICK_START.md](QUICK_START.md)** - 5-minute getting started guide

### Business Documentation  
- **[EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md)** - Business value proposition and ROI analysis
- **[DISTRIBUTION_GUIDE.md](DISTRIBUTION_GUIDE.md)** - Guidelines for different audiences

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
1. [EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md) - ROI and business benefits
2. [README.md](README.md) - Feature overview and competitive advantages
3. [Commercial Features](site/commercial-features.html) - Premium capabilities

### 👨‍💻 For Developers
1. [QUICK_START.md](QUICK_START.md) - Get running in 5 minutes
2. [examples/basic-setup/](examples/basic-setup/) - Basic configuration examples
3. [API Documentation](api/) - Technical API reference
4. [examples/ci-cd/](examples/ci-cd/) - CI/CD integration examples

### 🛡️ For Security Teams
1. [Security Features](site/security-features.html) - Security scanning capabilities
2. [examples/enterprise-setup/](examples/enterprise-setup/) - Advanced configuration with commercial features
3. [Commercial Features](site/commercial-features.html) - Premium security capabilities

### 🔧 For Operations Teams
1. [INSTALLATION.md](INSTALLATION.md) - Deployment and installation
2. [Configuration Reference](site/configuration.html) - Complete parameter guide
3. [examples/production-deployment/](examples/production-deployment/) - Production setup
4. [Monitoring Guide](examples/monitoring/) - Performance and health monitoring

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

Bastion is designed as a multi-module Maven project:

```
bastion-maven-plugin/
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
mvn mu.dodogeny:bastion-maven-plugin:${project.version}:scan
```

### 3. Review Results
Check `target/bastion-reports/` for generated security reports.

### 4. Configure for Your Needs
- **Basic Setup**: [examples/basic-setup/](examples/basic-setup/)
- **Enterprise Setup**: [examples/enterprise-setup/](examples/enterprise-setup/)
- **CI/CD Integration**: [examples/ci-cd/](examples/ci-cd/)

## 📞 Support & Resources

### Community Support (Open Source)
- **Email**: it.dodogeny@gmail.com
- **GitHub Issues**: [https://github.com/dodogeny/bastion-maven-plugin/issues](https://github.com/dodogeny/bastion-maven-plugin/issues)
- **Stack Overflow**: Use tag `bastion-maven-plugin`
- **Documentation**: [https://docs.dodogeny.mu/bastion](https://docs.dodogeny.mu/bastion)

### Enterprise Support (Commercial)
- **Email**: it.dodogeny@gmail.com
- **Priority Queue**: Guaranteed response within business hours
- **Professional Services**: Custom integrations and training
- **Phone Support**: Available with Premium plans

### Additional Resources
- **Official Website**: [https://bastion.dodogeny.mu](https://bastion.dodogeny.mu)
- **Blog & Tutorials**: [https://blog.dodogeny.mu/bastion](https://blog.dodogeny.mu/bastion)
- **Commercial Licensing**: [https://bastion.dodogeny.mu/pricing](https://bastion.dodogeny.mu/pricing)

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
- **Purchase**: [https://bastion.dodogeny.mu/pricing](https://bastion.dodogeny.mu/pricing)

---

**Thank you for choosing Bastion Maven Plugin!**

*Your enterprise fortress against security vulnerabilities*  
*Developed with ❤️ by [Dodogeny](https://dodogeny.mu) in Mauritius 🇲🇺*