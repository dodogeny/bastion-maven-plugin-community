# Smart NVD Database Caching

The Bastion Maven Plugin now includes intelligent caching for the OWASP NVD (National Vulnerability Database) to dramatically reduce scan times by avoiding unnecessary database downloads.

## How It Works

The smart caching system:

1. **Checks Remote Changes**: Before downloading, it queries the NVD servers to check if the database has been modified since the last download
2. **Validates Local Cache**: Compares local cache timestamps with remote modification times
3. **Downloads Only When Needed**: Only downloads the database if there are actual changes
4. **Configurable Validity**: Allows customization of cache validity periods

## Benefits

- **Faster Scans**: Subsequent scans are significantly faster when the NVD database hasn't changed
- **Reduced Bandwidth**: Avoids downloading large database files unnecessarily  
- **Better Reliability**: Falls back gracefully when cache checks fail
- **API Key Optimization**: Uses different caching strategies based on whether you have an NVD API key

## Configuration

### Basic Configuration

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin</artifactId>
    <version>1.1.0</version>
    <configuration>
        <!-- Enable automatic updates (required for caching to work) -->
        <autoUpdate>true</autoUpdate>
        
        <!-- Smart caching is enabled by default -->
        <smartCachingEnabled>true</smartCachingEnabled>
        
        <!-- Cache validity period in hours (default: 6 hours) -->
        <cacheValidityHours>6</cacheValidityHours>
        
        <!-- Optional: specify cache directory -->
        <cacheDirectory>${user.home}/.bastion/nvd-cache</cacheDirectory>
    </configuration>
</plugin>
```

### Advanced Configuration with NVD API Key

```xml
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>bastion-maven-plugin</artifactId>
    <version>1.1.0</version>
    <configuration>
        <autoUpdate>true</autoUpdate>
        <nvdApiKey>${nvd.api.key}</nvdApiKey>
        
        <!-- With API key, you can check more frequently -->
        <cacheValidityHours>3</cacheValidityHours>
        <smartCachingEnabled>true</smartCachingEnabled>
    </configuration>
</plugin>
```

### System Properties

You can also configure caching via system properties:

```bash
mvn bastion:scan \
  -Dbastion.nvd.apiKey=your-api-key \
  -Dbastion.cache.validity.hours=12 \
  -Dbastion.smart.caching.enabled=true
```

## Cache Behavior

### With NVD API Key
- **First Run**: Downloads full NVD database (~500MB+)
- **Subsequent Runs**: Checks remote database modification time
- **If Unchanged**: Uses cached database (scan starts immediately)
- **If Updated**: Downloads latest changes only
- **Default Check Interval**: 6 hours

### Without NVD API Key  
- **First Run**: Downloads full NVD database
- **Subsequent Runs**: Uses time-based caching (more conservative)
- **Cache Validity**: 24 hours by default
- **Fallback**: Always downloads if remote check fails

## Cache Management

### View Cache Status

The plugin will log cache decisions during scans:

```
[INFO] 🔍 Checking NVD database cache status...
[INFO] ✅ NVD cache is valid - skipping database download
[INFO] 🔑 NVD API key configured - CVE analysis enabled, cache status: using cached database
```

### Clear Cache

To force a fresh download, you can clear the cache:

```bash
# Delete the cache directory
rm -rf ~/.bastion/nvd-cache

# Or run with disabled caching for one scan
mvn bastion:scan -Dbastion.smart.caching.enabled=false
```

### Cache Location

By default, the cache is stored in:
- Linux/Mac: `~/.bastion/nvd-cache/`
- Windows: `%USERPROFILE%\.bastion\nvd-cache\`

You can customize this with the `cacheDirectory` configuration parameter.

## Performance Impact

### Before Smart Caching
```
[INFO] Starting OWASP Dependency-Check scan...
[INFO] Downloading NVD database... (5-10 minutes)
[INFO] Analyzing dependencies... (2-3 minutes)
[INFO] Total scan time: 8-13 minutes
```

### With Smart Caching (cache hit)
```
[INFO] 🔍 Checking NVD database cache status...
[INFO] ✅ NVD cache is valid - skipping database download
[INFO] Starting OWASP Dependency-Check scan...
[INFO] Analyzing dependencies... (2-3 minutes)
[INFO] Total scan time: 2-3 minutes
```

## Troubleshooting

### Cache Check Failures

If cache validation fails, the system falls back to downloading:

```
[WARN] ⚠️ Error checking cache validity, defaulting to update: Connection timeout
[INFO] 🔄 NVD cache is stale or remote database updated - will download latest
```

### Disable Caching Temporarily

```bash
mvn bastion:scan -Dbastion.smart.caching.enabled=false
```

### Debug Cache Behavior

Enable debug logging to see detailed cache decisions:

```bash
mvn bastion:scan -X -Dorg.slf4j.simpleLogger.log.io.github.dodogeny=debug
```

## Best Practices

1. **Use NVD API Key**: Get a free API key from NIST for better caching behavior
2. **CI/CD Pipelines**: Set longer cache validity (12-24 hours) for build pipelines
3. **Development**: Use shorter validity (2-6 hours) for active development
4. **Monitor Logs**: Watch for cache hit/miss messages to optimize settings

## Migration from Previous Versions

The smart caching is automatically enabled and backward compatible. Your existing configuration will work unchanged, with caching providing performance benefits automatically.

No action is required to upgrade - the first scan will establish the cache, and subsequent scans will be faster.