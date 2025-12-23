# Dynamic Version Management

## Overview

This project uses a dynamic versioning system to ensure that all documentation and samples automatically reference the current version defined in the parent POM's `<revision>` property. This eliminates the need to manually update version numbers across multiple files when releasing a new version.

## How It Works

### 1. Single Source of Truth

The version is defined once in the parent `pom.xml`:

```xml
<properties>
    <revision>1.2.4</revision>
</properties>
```

All child modules inherit this version through:

```xml
<parent>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin-parent</artifactId>
    <version>${revision}</version>
</parent>
```

### 2. Maven Resource Filtering

The parent POM is configured to filter documentation files during the build process:

```xml
<build>
    <resources>
        <resource>
            <directory>${project.basedir}</directory>
            <includes>
                <include>README.md</include>
                <include>QUICKSTART.md</include>
                <include>CHANGELOG.md</include>
            </includes>
            <filtering>true</filtering>
            <targetPath>${project.build.directory}/filtered-docs</targetPath>
        </resource>
    </resources>
</build>
```

### 3. Version Placeholders in Documentation

Instead of hardcoding version numbers, documentation files use the `@project.version@` placeholder:

**Before (Hardcoded):**
```xml
<version>1.2.1</version>
```

**After (Dynamic):**
```xml
<version>@project.version@</version>
```

### 4. Build-Time Replacement

During the Maven build process:
1. Maven processes resources (including markdown files)
2. Replaces `@project.version@` with the actual version from `<revision>`
3. Outputs filtered files to `target/filtered-docs/`

## Release Process

When creating a new release:

1. **Update Version Once**: Edit only the `<revision>` property in the parent `pom.xml`:
   ```xml
   <revision>1.2.5</revision>
   ```

2. **Build Project**: Run Maven build to generate filtered documentation:
   ```bash
   mvn clean package
   ```

3. **Verify**: Check `target/filtered-docs/` to ensure versions are correctly replaced

4. **Commit & Release**: The CI/CD pipeline automatically:
   - Extracts the version from `<revision>`
   - Builds with the correct version
   - Deploys to Maven Central
   - Creates GitHub release with updated documentation

## CI/CD Integration

The `.github/workflows/release.yml` workflow:

1. **Extracts Version**:
   ```yaml
   - name: Step 4 - Extract base version from POM
     run: |
       POM_VERSION=$(grep -oP '<revision>\K[^<]+' pom.xml | head -1)
       echo "pom_version=$POM_VERSION" >> $GITHUB_OUTPUT
   ```

2. **Uses Version Throughout Pipeline**:
   - Build step uses `${{ steps.pom_version.outputs.pom_version }}`
   - Deploy step passes `-Drevision=${{ steps.final_version.outputs.version }}`
   - Release notes reference the correct version

3. **Generates Release Notes**: Automatically creates changelog from git commits and formats release with the correct version

## Files Using Dynamic Versioning

### Documentation Files
- `README.md` - All version references use `@project.version@`
- `QUICKSTART.md` - All version references use `@project.version@`
- `CHANGELOG.md` - Version headers (manual updates still needed for changelog entries)

### Example POM Files
- `distribution/src/main/examples/basic-setup/pom.xml` - Uses version range `[1.2.0,)` for flexibility
- `distribution/src/main/examples/enterprise-setup/pom.xml` - Uses version range `[1.2.0,)` for flexibility

**Note**: Example POMs use version ranges instead of exact versions to automatically pick up latest releases.

## Benefits

1. **Single Update Point**: Change version once in parent POM
2. **Consistency**: All documentation always references the correct version
3. **No Manual Updates**: Eliminates human error from forgetting to update version in docs
4. **CI/CD Friendly**: Automated builds use the correct version automatically
5. **Release Efficiency**: Faster releases with fewer manual steps

## Troubleshooting

### Problem: Documentation shows `@project.version@` instead of actual version

**Solution**: You're viewing the source files directly. Run Maven build first:
```bash
mvn clean package
cat target/filtered-docs/README.md  # View filtered version
```

### Problem: Want to preview documentation with version replaced

**Solution**: Use the maven-resources-plugin directly:
```bash
mvn resources:resources
cat target/filtered-docs/README.md
```

### Problem: Need to use a different version for testing

**Solution**: Override via command line:
```bash
mvn clean package -Drevision=1.2.5-SNAPSHOT
```

## Migration Guide (For Future Reference)

If you need to add a new documentation file to the dynamic versioning system:

1. Add the file to the parent POM's resources configuration:
   ```xml
   <resource>
       <directory>${project.basedir}</directory>
       <includes>
           <include>README.md</include>
           <include>QUICKSTART.md</include>
           <include>YOUR_NEW_FILE.md</include>
       </includes>
       <filtering>true</filtering>
       <targetPath>${project.build.directory}/filtered-docs</targetPath>
   </resource>
   ```

2. Replace hardcoded versions in the new file with `@project.version@`

3. Build and verify:
   ```bash
   mvn clean package
   cat target/filtered-docs/YOUR_NEW_FILE.md
   ```

## Best Practices

1. **Always Update `<revision>` First**: Before any release, update the revision property
2. **Test Build Locally**: Run `mvn clean package` to verify filtering works
3. **Check Filtered Output**: Review `target/filtered-docs/` before releasing
4. **Commit Source Files**: Only commit files with `@project.version@`, never filtered versions
5. **Document Version Changes**: Update CHANGELOG.md with what changed in each version

## Related Files

- `pom.xml` - Parent POM with `<revision>` property and resource filtering config
- `.github/workflows/release.yml` - CI/CD workflow that extracts and uses the version
- `README.md` - Main documentation with dynamic version placeholders
- `QUICKSTART.md` - Quick start guide with dynamic version placeholders
- `distribution/src/main/examples/*/pom.xml` - Example configurations

---

**Last Updated**: 2025-12-18
**Implemented By**: Dynamic version management system
**Version Management**: Maven resource filtering with `@project.version@` placeholders
