# Release Workflow Improvements

## Overview

This document outlines the improvements made to the GitHub Actions release workflow (`release-improved.yml`), comparing it with the original workflow and explaining the benefits of each enhancement.

## Key Improvements Summary

| Feature | Original | Improved | Benefit |
|---------|----------|----------|---------|
| Pre-flight checks | ❌ None | ✅ Comprehensive | Prevents failed releases |
| Version validation | ❌ None | ✅ Semver validation | Ensures valid versions |
| Tag existence check | ❌ Basic | ✅ Smart checking | Avoids duplicate releases |
| Test execution | ❌ No tests | ✅ Full test suite | Quality assurance |
| Artifact verification | ❌ Minimal | ✅ Complete | Ensures completeness |
| Checksums | ❌ None | ✅ SHA-256 | Security & integrity |
| CHANGELOG extraction | ❌ Git only | ✅ CHANGELOG.md first | Professional notes |
| Dry run mode | ❌ None | ✅ Manual trigger | Safe testing |
| Error handling | ❌ Basic | ✅ Comprehensive | Better diagnostics |
| Job separation | ❌ 2 jobs | ✅ 6 jobs | Better organization |
| Release summary | ❌ None | ✅ Detailed | Easy monitoring |
| Artifact storage | ❌ None | ✅ GitHub Artifacts | Persistence |

## Detailed Improvements

### 1. Pre-flight Checks Job

**Purpose**: Validate everything before starting expensive operations

**Features**:
- ✅ Extract and validate version from POM
- ✅ Semver format validation (MAJOR.MINOR.PATCH)
- ✅ Tag existence check to avoid duplicates
- ✅ CHANGELOG entry validation
- ✅ Previous version detection for comparison
- ✅ Manual version override support

**Benefits**:
- Fails fast if version is invalid
- Prevents duplicate releases
- Warns about missing CHANGELOG entries
- Saves time by catching errors early

**Example Output**:
```
✓ Using POM version: 1.2.5
✓ Version format is valid: 1.2.5
✓ Tag v1.2.5 does not exist yet
✓ CHANGELOG entry found
Previous version: v1.2.4
```

### 2. Build and Test Job

**Purpose**: Comprehensive build verification before release

**New Features**:
- ✅ **Test Execution**: Runs full test suite before building
- ✅ **Build Environment Display**: Shows Java, Maven, OS versions
- ✅ **Artifact Verification**: Verifies all expected files exist
- ✅ **Size Reporting**: Shows file sizes of distributions
- ✅ **Checksum Generation**: Creates SHA-256 checksums for all artifacts
- ✅ **Artifact Upload**: Stores build artifacts for later jobs

**Benefits**:
- Quality assurance through testing
- Early detection of build failures
- Security through checksums
- Artifact persistence across jobs
- Better debugging with environment info

**Example Output**:
```
=== Verifying Distribution Artifacts ===
✓ sechive-maven-plugin-1.2.5-bin.zip (25M)
✓ sechive-maven-plugin-1.2.5-bin-unix.tar.gz (24M)
✓ sechive-maven-plugin-1.2.5-docs.zip (12M)
✓ sechive-maven-plugin-1.2.5-src.zip (2.1M)
✓ sechive-maven-plugin-1.2.5-src.tar.gz (1.9M)
✓ All artifacts present

=== Generating SHA-256 Checksums ===
✓ Generated checksum for sechive-maven-plugin-1.2.5-bin.zip
✓ Generated checksum for sechive-maven-plugin-1.2.5-bin-unix.tar.gz
...
```

### 3. Release to Maven Central Job

**Purpose**: Secure and verified deployment to Maven Central

**Improvements**:
- ✅ **GPG Key Verification**: Validates keys were imported correctly
- ✅ **Secret Validation**: Checks all required secrets are set
- ✅ **Conditional Execution**: Skips if dry run mode
- ✅ **Better Error Messages**: Clear failure reasons
- ✅ **Skip Tests**: Avoids re-running tests (already done in build job)

**Benefits**:
- More secure deployment process
- Better error diagnostics
- Faster deployment (no redundant tests)
- Dry run capability for testing

**Example Output**:
```
✓ GPG keys imported successfully
✓ All required secrets are configured
=== Deploying version 1.2.5 to Maven Central ===
✓ Deployment completed
```

### 4. GitHub Release Job

**Purpose**: Create comprehensive GitHub release with all artifacts

**Major Improvements**:
- ✅ **CHANGELOG Extraction**: Pulls release notes from CHANGELOG.md
- ✅ **Git Commit Fallback**: Uses git history if CHANGELOG missing
- ✅ **Checksum Inclusion**: Adds SHA-256 checksums to release
- ✅ **Artifact Download**: Gets artifacts from build job
- ✅ **Enhanced Release Notes**: Professional formatting with sections
- ✅ **Maven Central Links**: Direct links to artifact pages

**Benefits**:
- Professional release notes from CHANGELOG
- Complete artifact set with security files
- Easy verification with checksums
- Direct links to resources

**Release Notes Sections**:
1. Installation instructions
2. What's Changed (from CHANGELOG or git)
3. Maven Central deployment info
4. Artifact descriptions
5. Verification instructions (GPG + checksums)
6. Comparison link to previous release

### 5. Post-Release Verification Job

**Purpose**: Verify release succeeded completely

**Features**:
- ✅ **GitHub Release Verification**: Confirms release exists
- ✅ **Asset Count Check**: Validates expected artifacts
- ✅ **Maven Central Check**: Attempts to verify Maven Central availability
- ✅ **Async Check**: Doesn't fail if Maven Central not synced yet

**Benefits**:
- Confidence in successful release
- Early detection of issues
- Helpful for debugging
- Informative about Maven Central sync time

**Example Output**:
```
=== Verifying GitHub Release ===
✓ Release exists with 16 assets

=== Checking Maven Central Availability ===
⏳ Artifact not yet available on Maven Central (this is normal)
Check status at: https://central.sonatype.com/...
```

### 6. Release Summary Job

**Purpose**: Provide at-a-glance overview of release status

**Features**:
- ✅ **Job Status Table**: Shows pass/fail for each job
- ✅ **Release Links**: Direct links to GitHub and Maven Central
- ✅ **Trigger Info**: Shows how workflow was triggered
- ✅ **GitHub Summary**: Formatted markdown summary

**Benefits**:
- Easy monitoring of release pipeline
- Quick access to release resources
- Historical record in workflow runs
- Professional presentation

**Example Summary**:
```markdown
# 🚀 Release Summary

**Version**: v1.2.5
**Dry Run**: false
**Trigger**: push

## Job Status
| Job | Status |
|-----|--------|
| Pre-flight | success |
| Build | success |
| Maven Central Release | success |
| GitHub Release | success |
| Verification | success |

## 📦 Release Links
- [GitHub Release](https://github.com/.../releases/tag/v1.2.5)
- [Maven Central](https://central.sonatype.com/.../1.2.5)
- [Deployment Status](https://central.sonatype.com/publishing/deployments)
```

## New Workflow Inputs

### Manual Workflow Dispatch

The improved workflow supports manual triggering with options:

```yaml
workflow_dispatch:
  inputs:
    dry_run:
      description: 'Dry run (skip Maven Central deployment and GitHub release)'
      default: false
      type: boolean
    force_version:
      description: 'Force specific version (leave empty to use POM version)'
      type: string
```

**Use Cases**:

1. **Dry Run Mode**: Test the workflow without deploying
   ```bash
   # From GitHub UI: Actions → Release → Run workflow
   # Set "Dry run" to true
   ```
   - Runs build and tests
   - Skips Maven Central deployment
   - Skips GitHub release creation
   - Perfect for testing changes

2. **Force Version**: Override POM version
   ```bash
   # From GitHub UI: Set "Force version" to 1.2.6-RC1
   ```
   - Useful for release candidates
   - Useful for hotfix releases
   - Still validates semver format

## Environment Variables

The workflow uses consistent environment variables:

```yaml
env:
  JAVA_VERSION: 21
  MAVEN_OPTS: "-Xmx2g -XX:+UseG1GC"
```

**Benefits**:
- Single point of configuration
- Consistent across all jobs
- Easy to update Java version

## Error Handling

### Fail-Fast Validation

The workflow fails fast when:
- Version format is invalid
- Tag already exists (auto-trigger only)
- Required secrets are missing
- GPG keys fail to import
- Expected artifacts are missing
- Tests fail

### Graceful Degradation

The workflow continues when:
- CHANGELOG entry is missing (warning only)
- Maven Central not yet synced (informational)
- Auto-version increment fails (falls back to POM)

## Security Enhancements

### 1. Checksums (SHA-256)

Every artifact gets a checksum file:
```bash
sechive-maven-plugin-1.2.5-bin.zip
sechive-maven-plugin-1.2.5-bin.zip.sha256  # NEW
```

Users can verify:
```bash
sha256sum -c sechive-maven-plugin-1.2.5-bin.zip.sha256
```

### 2. GPG Key Validation

The workflow verifies GPG keys were imported:
```bash
if gpg --list-secret-keys --keyid-format=long | grep -q sec; then
  echo "✓ GPG keys imported successfully"
else
  exit 1
fi
```

### 3. Secret Validation

Checks all required secrets before deployment:
```bash
MISSING=0
if [ -z "$OSSRH_USERNAME" ]; then
  MISSING=$((MISSING + 1))
fi
# ... check all secrets
if [ $MISSING -gt 0 ]; then
  exit 1
fi
```

## Performance Optimizations

### 1. Job Separation

**Before**: 2 monolithic jobs
**After**: 6 focused jobs

Benefits:
- Parallel execution where possible
- Better failure isolation
- Clearer progress tracking
- Easier debugging

### 2. Artifact Caching

Build artifacts are uploaded once and reused:
```yaml
- uses: actions/upload-artifact@v4
  with:
    name: distribution-${{ needs.preflight.outputs.version }}
    path: distribution/target/*
```

Benefits:
- No need to rebuild for GitHub release
- Ensures exact same artifacts
- Faster workflow execution

### 3. Smart Caching

Maven dependencies cached across jobs:
```yaml
- uses: actions/setup-java@v4
  with:
    cache: maven
```

### 4. Conditional Execution

Jobs skip when appropriate:
```yaml
if: |
  needs.preflight.outputs.should_release == 'true' &&
  github.event.inputs.dry_run != 'true'
```

## Migration Guide

### Option 1: Replace Current Workflow

```bash
# Backup current workflow
mv .github/workflows/release.yml .github/workflows/release-old.yml

# Use improved workflow
mv .github/workflows/release-improved.yml .github/workflows/release.yml

# Commit
git add .github/workflows/
git commit -m "Upgrade to improved release workflow"
```

### Option 2: Side-by-Side Testing

```bash
# Keep both workflows
# Test improved workflow with manual trigger and dry run
# Switch when confident
```

### Required Secrets

Ensure these secrets are configured in GitHub:
- `OSSRH_USERNAME` - Maven Central username
- `OSSRH_TOKEN` - Maven Central token
- `GPG_PUBLIC_KEY` - GPG public key
- `GPG_SECRET_KEY` - GPG private key
- `GPG_PASSPHRASE` - GPG key passphrase
- `GITHUB_TOKEN` - (automatically provided)

## Testing the Workflow

### Test with Dry Run

1. Go to Actions → Continuous Delivery Release
2. Click "Run workflow"
3. Select branch: `main`
4. Check "Dry run"
5. Click "Run workflow"

This will:
- ✅ Run all pre-flight checks
- ✅ Run full build and tests
- ✅ Generate checksums
- ❌ Skip Maven Central deployment
- ❌ Skip GitHub release creation

### Test with Release Candidate

1. Update POM: `<revision>1.2.6-RC1</revision>`
2. Commit and push
3. Workflow runs automatically
4. Validates version format (allows `-RC1` suffix)
5. Creates release with RC version

## Troubleshooting

### Problem: Pre-flight fails with "Tag already exists"

**Cause**: Trying to release a version that was already released

**Solution**:
- Increment version in POM
- Or use manual trigger with `force_version`
- Or delete the tag if it was a mistake

### Problem: Build fails with missing artifacts

**Cause**: Maven build didn't create all expected files

**Solution**:
- Check Maven build logs
- Verify distribution/pom.xml assembly configurations
- Ensure all modules build correctly

### Problem: Maven Central check always fails

**Cause**: Maven Central takes up to 30 minutes to sync

**Solution**:
- This is normal and expected
- The job continues (doesn't fail workflow)
- Check again later at the provided URL

### Problem: CHANGELOG warning appears

**Cause**: No entry for current version in CHANGELOG.md

**Solution**:
- Add entry to CHANGELOG.md before release
- Or ignore (workflow falls back to git commits)

## Comparison Matrix

| Aspect | Original | Improved | Improvement |
|--------|----------|----------|-------------|
| **Pre-checks** | None | Version validation, tag check, CHANGELOG | 🟢 Safety |
| **Testing** | None | Full test suite | 🟢 Quality |
| **Artifacts** | Basic check | Size, checksums, verification | 🟢 Security |
| **Release Notes** | Git commits | CHANGELOG.md extraction | 🟢 Professional |
| **Error Handling** | Basic | Comprehensive validation | 🟢 Reliability |
| **Dry Run** | No | Yes (manual trigger) | 🟢 Testing |
| **Job Organization** | 2 jobs | 6 specialized jobs | 🟢 Clarity |
| **Verification** | None | Post-release checks | 🟢 Confidence |
| **Summary** | None | Detailed status table | 🟢 Monitoring |
| **Performance** | Rebuild each job | Artifact reuse | 🟢 Speed |
| **Documentation** | Inline | This guide | 🟢 Maintainability |

## Best Practices

### 1. Always Update CHANGELOG First

Before releasing:
```bash
# Edit CHANGELOG.md
vim CHANGELOG.md

# Add entry for new version
## [1.2.6] - 2025-12-XX
### Added
- Feature X
### Fixed
- Bug Y

# Commit
git commit -am "Update CHANGELOG for v1.2.6"
```

### 2. Test with Dry Run

Before important releases:
```bash
# Manual trigger with dry run
# GitHub UI → Actions → Run workflow → Dry run: true
```

### 3. Monitor Summary

After release:
- Check workflow summary for status
- Verify all jobs succeeded
- Click release links to verify

### 4. Version Bumps

For version bumps:
```bash
# Edit POM
sed -i 's/<revision>1.2.5<\/revision>/<revision>1.2.6<\/revision>/' pom.xml

# Commit
git commit -am "Bump version to 1.2.6"

# Push (triggers release)
git push origin main
```

## Future Enhancements

Potential future improvements:

1. **Notification System**: Slack/Discord notifications on release
2. **Performance Metrics**: Track build times, artifact sizes over time
3. **Vulnerability Scanning**: Scan dependencies before release
4. **License Check**: Verify all dependencies have acceptable licenses
5. **Documentation Deployment**: Auto-deploy docs to GitHub Pages
6. **Release Approval**: Require manual approval before Maven Central
7. **Rollback Workflow**: Automate rollback of failed releases
8. **Multi-Platform Builds**: Build on Linux, macOS, Windows
9. **Container Images**: Build and push Docker images
10. **API Testing**: Integration tests against deployed artifacts

## Support

For issues with the workflow:
- Check workflow logs in GitHub Actions
- Review this documentation
- Create issue on GitHub with workflow run URL
- Email: it.dodogeny@gmail.com

---

**Last Updated**: 2025-12-18
**Workflow Version**: 2.0 (Improved)
**Maintained By**: SecHive Maven Plugin Team
