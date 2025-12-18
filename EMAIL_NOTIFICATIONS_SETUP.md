# Email Notifications Setup Guide

## Overview

The improved release workflow includes automatic email notifications sent to a distribution list after successful deployment to Maven Central. This guide explains how to configure and customize email notifications.

## Features

### Professional HTML Email Template

The notification email includes:
- 🎨 **Beautiful HTML design** with gradient header and styled sections
- 📊 **Release statistics** (version, commits, PRs, contributors)
- 💻 **Installation instructions** with code snippets
- 📦 **Artifact list** with sizes and descriptions
- 🔗 **Quick links** to GitHub release, Maven Central, documentation
- ℹ️ **Deployment metadata** (timestamp, workflow run, commit, actor)
- 📧 **Plain text fallback** for email clients that don't support HTML

### Release Notes Enhancement

Release notes are now generated with:
- ✅ **Categorized commits** by type (Features, Bug Fixes, Documentation, etc.)
- ✅ **PR references** automatically extracted from commit messages
- ✅ **Clickable commit hashes** linking to GitHub
- ✅ **Author attribution** for each commit
- ✅ **CHANGELOG.md integration** (uses CHANGELOG if available, falls back to commits)

## Required GitHub Secrets

You need to configure the following secrets in your GitHub repository:

### 1. SMTP Credentials

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `SMTP_USERNAME` | SMTP server username (usually your email) | `your-email@gmail.com` |
| `SMTP_PASSWORD` | SMTP server password or app-specific password | `your-app-password` |

### 2. Distribution Email

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `RELEASE_NOTIFICATION_EMAIL` | Email address to receive release notifications | `releases@yourcompany.com` or `team@example.com, admin@example.com` |

**Note**: For multiple recipients, use comma-separated values:
```
team@example.com, releases@example.com, notifications@example.com
```

## Setup Instructions

### Step 1: Configure SMTP Provider

#### Option A: Gmail (Recommended for Personal Use)

1. **Enable 2-Step Verification**:
   - Go to https://myaccount.google.com/security
   - Enable 2-Step Verification

2. **Create App Password**:
   - Go to https://myaccount.google.com/apppasswords
   - Select app: "Mail"
   - Select device: "Other (Custom name)"
   - Enter name: "GitHub Actions - Bastion Release"
   - Click "Generate"
   - Copy the 16-character password

3. **Configure Secrets**:
   ```
   SMTP_USERNAME: your-email@gmail.com
   SMTP_PASSWORD: xxxx xxxx xxxx xxxx (app password)
   ```

#### Option B: SendGrid (Recommended for Production)

1. **Create SendGrid Account**:
   - Sign up at https://sendgrid.com
   - Verify your email and domain

2. **Create API Key**:
   - Go to Settings → API Keys
   - Create API Key with "Mail Send" permissions
   - Copy the API key

3. **Configure Secrets**:
   ```
   SMTP_USERNAME: apikey
   SMTP_PASSWORD: SG.xxxxxxxxxxxx (API key)
   ```

4. **Update Workflow** (change SMTP server):
   ```yaml
   server_address: smtp.sendgrid.net
   server_port: 587
   ```

#### Option C: Amazon SES (Recommended for AWS Users)

1. **Set up SES**:
   - Go to AWS SES Console
   - Verify your sending email address
   - Create SMTP credentials

2. **Configure Secrets**:
   ```
   SMTP_USERNAME: your-ses-username
   SMTP_PASSWORD: your-ses-password
   ```

3. **Update Workflow**:
   ```yaml
   server_address: email-smtp.us-east-1.amazonaws.com
   server_port: 587
   ```

#### Option D: Microsoft 365 / Outlook

1. **Configure Secrets**:
   ```
   SMTP_USERNAME: your-email@outlook.com
   SMTP_PASSWORD: your-password
   ```

2. **Update Workflow**:
   ```yaml
   server_address: smtp-mail.outlook.com
   server_port: 587
   ```

### Step 2: Add GitHub Secrets

1. **Go to Repository Settings**:
   - Navigate to your repository on GitHub
   - Click "Settings" → "Secrets and variables" → "Actions"

2. **Add Secrets**:
   - Click "New repository secret"
   - Add each secret:

   ```
   Name: SMTP_USERNAME
   Value: your-email@gmail.com
   ```

   ```
   Name: SMTP_PASSWORD
   Value: your-app-password
   ```

   ```
   Name: RELEASE_NOTIFICATION_EMAIL
   Value: releases@yourcompany.com
   ```

3. **Verify Secrets**:
   - Secrets should appear in the list (values are hidden)
   - You should see 3 new secrets

### Step 3: Test Email Notification

1. **Trigger Workflow with Dry Run**:
   - Go to Actions → Continuous Delivery Release
   - Click "Run workflow"
   - Check "Dry run" option
   - Run workflow

   **Note**: Dry run skips email notification by design. For full test, proceed to step 2.

2. **Test with Real Release**:
   - Make a small change (e.g., update README)
   - Commit and push to main
   - Workflow triggers automatically
   - Check email inbox for notification

3. **Verify Email Received**:
   - Check inbox at the configured email address
   - Email subject: "✅ Bastion Maven Plugin vX.X.X Released to Maven Central"
   - Verify HTML rendering and all links work

## Email Content Structure

### HTML Email Preview

```
┌─────────────────────────────────────────────────────────┐
│  🚀 Bastion Maven Plugin Community v1.2.5               │
│  Successfully Released to Maven Central                 │
│  ✓ Build Successful                                     │
├─────────────────────────────────────────────────────────┤
│  📊 Release Statistics                                  │
│  ┌──────────┬──────────┬──────────┬──────────┐        │
│  │  1.2.5   │    42    │    5     │    3     │        │
│  │ Version  │ Commits  │   PRs    │Contributors│      │
│  └──────────┴──────────┴──────────┴──────────┘        │
├─────────────────────────────────────────────────────────┤
│  💻 Installation                                        │
│  <plugin>                                               │
│    <version>1.2.5</version>                             │
│  </plugin>                                              │
├─────────────────────────────────────────────────────────┤
│  📦 Distribution Artifacts                              │
│  • Windows/Cross-Platform: ... (25M)                    │
│  • Unix/Linux/macOS: ... (24M)                          │
│  • Documentation: ... (12M)                             │
│  • Source Code: ... (.zip & .tar.gz)                    │
├─────────────────────────────────────────────────────────┤
│  📝 What's Changed                                      │
│  42 commits since v1.2.4                                │
│  View detailed release notes...                         │
├─────────────────────────────────────────────────────────┤
│  🔗 Quick Links                                         │
│  [View Release on GitHub] [View on Maven Central]      │
│  [Repository] [Documentation]                           │
├─────────────────────────────────────────────────────────┤
│  ℹ️ Deployment Information                              │
│  • Released: 2025-12-18 15:30:42 UTC                    │
│  • Workflow: View workflow run                          │
│  • Commit: abc123def                                    │
│  • Triggered by: username                               │
└─────────────────────────────────────────────────────────┘
```

### Plain Text Fallback

For email clients that don't support HTML, a plain text version is automatically included:

```
Bastion Maven Plugin Community v1.2.5 Released

Release Statistics:
- Version: 1.2.5
- Commits: 42
- Pull Requests: 5
- Contributors: 3

Installation:
<plugin>
  <groupId>io.github.dodogeny</groupId>
  <artifactId>bastion-maven-community-plugin</artifactId>
  <version>1.2.5</version>
</plugin>

Distribution Artifacts:
- Windows/Cross-Platform: bastion-maven-plugin-1.2.5-bin.zip (25M)
- Unix/Linux/macOS: bastion-maven-plugin-1.2.5-bin-unix.tar.gz (24M)
- Documentation: bastion-maven-plugin-1.2.5-docs.zip (12M)
- Source Code: Available in .zip and .tar.gz formats

Quick Links:
- GitHub Release: https://github.com/.../releases/tag/v1.2.5
- Maven Central: https://central.sonatype.com/.../1.2.5

Deployment Information:
- Released: 2025-12-18 15:30:42 UTC
- Workflow Run: https://github.com/.../actions/runs/...
- Commit: abc123def
- Triggered by: username
```

## Enhanced Release Notes

### Commit Categorization

The workflow automatically categorizes commits by type:

#### 🚀 Features & Enhancements
Matches: `feat:`, `feature:`, `add:`, `added:`, `new:`

```markdown
- feat: Add dynamic version management (#42) by @user (abc123)
- add: Email notification system (#45) by @contributor (def456)
```

#### 🐛 Bug Fixes
Matches: `fix:`, `fixed:`, `bugfix:`, `bug:`

```markdown
- fix: Resolve checksum generation issue (#43) by @user (ghi789)
- bugfix: Correct SMTP configuration (#46) by @maintainer (jkl012)
```

#### 📚 Documentation
Matches: `docs:`, `doc:`, `documentation:`

```markdown
- docs: Update release workflow guide (#44) by @writer (mno345)
- doc: Add email notification setup instructions by @author (pqr678)
```

#### 🔧 Maintenance & Chores
Matches: `chore:`, `refactor:`, `test:`, `ci:`, `build:`, `perf:`

```markdown
- chore: Update dependencies to latest versions by @maintainer (stu901)
- refactor: Improve release notes generation by @dev (vwx234)
```

#### 📦 Other Changes
All other commits that don't match above categories

### PR Reference Extraction

The workflow automatically detects and links pull requests:

**Commit Message**: `feat: Add email notifications (#42)`

**Generated Link**:
```markdown
- feat: Add email notifications by @user ([abc123](link)) [#42](pr-link)
```

### Example Release Notes Output

```markdown
## What's Changed

### Commits Since v1.2.4

#### 🚀 Features & Enhancements
- feat: Add dynamic version management (#42) by @dodogeny ([abc123](link)) [#42](pr-link)
- add: Email notification system (#45) by @contributor ([def456](link)) [#45](pr-link)

#### 🐛 Bug Fixes
- fix: Resolve checksum generation issue (#43) by @user ([ghi789](link)) [#43](pr-link)
- bugfix: Correct SMTP configuration (#46) by @maintainer ([jkl012](link)) [#46](pr-link)

#### 📚 Documentation
- docs: Update release workflow guide (#44) by @writer ([mno345](link)) [#44](pr-link)

#### 🔧 Maintenance & Chores
- chore: Update dependencies to latest versions by @maintainer ([stu901](link))
- refactor: Improve release notes generation by @dev ([vwx234](link))

#### 📦 Other Changes
- Bump version to 1.2.5 by @dodogeny ([yza567](link))
```

## Customization

### Change Email Template

Edit the email template in the workflow file:

```yaml
# .github/workflows/release-improved.yml
- name: Prepare email content
  run: |
    # Modify the HTML template here
    cat > email_body.html <<EOF
    <!DOCTYPE html>
    <html>
    ...
    </html>
    EOF
```

### Add Custom Sections

Add new sections to the email:

```yaml
<!-- Custom Section -->
<div class="section">
  <h2>🎯 Key Highlights</h2>
  <ul>
    <li>Feature 1 description</li>
    <li>Feature 2 description</li>
  </ul>
</div>
```

### Change SMTP Provider

Update the SMTP configuration:

```yaml
- name: Send email notification
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: your-smtp-server.com
    server_port: 587  # Use 587 for STARTTLS (don't set secure: true)
    # For SSL/TLS (port 465), add: secure: true
    username: ${{ secrets.SMTP_USERNAME }}
    password: ${{ secrets.SMTP_PASSWORD }}
```

### Add Multiple Recipients

Update the `RELEASE_NOTIFICATION_EMAIL` secret:

```
team@example.com, releases@example.com, notifications@example.com
```

Or configure in workflow:

```yaml
to: ${{ secrets.RELEASE_NOTIFICATION_EMAIL }}
cc: optional-cc@example.com
bcc: optional-bcc@example.com
```

### Customize Subject Line

Change the email subject:

```yaml
subject: "🚀 NEW RELEASE: Bastion v${{ needs.preflight.outputs.version }} - Check it out!"
```

### Add Attachments

Include files as attachments:

```yaml
attachments: |
  distribution/target/bastion-maven-plugin-${{ needs.preflight.outputs.version }}-bin.zip
  distribution/target/SHA256SUMS.txt
```

## Troubleshooting

### Problem: Email not received

**Possible Causes**:
1. Incorrect SMTP credentials
2. Email in spam folder
3. SMTP server blocking GitHub Actions IPs
4. Secret names don't match exactly

**Solutions**:
1. Verify SMTP credentials work with a test email client
2. Check spam/junk folder
3. Whitelist GitHub Actions IP ranges in SMTP provider
4. Double-check secret names (case-sensitive)
5. Check workflow logs for error messages

### Problem: Email sent but HTML not rendering

**Cause**: Email client doesn't support HTML or security settings block external images

**Solutions**:
1. Use an email client that supports HTML (Gmail, Outlook, etc.)
2. Check email client security settings
3. View plain text version (should always work)

### Problem: SMTP authentication failed

**Cause**: Using regular password instead of app password

**Solution** (Gmail):
1. Enable 2-Step Verification
2. Generate app-specific password
3. Use app password instead of regular password

### Problem: Release notes don't show PRs

**Cause**: Commit messages don't include PR references

**Solution**: Use conventional commit format with PR numbers:
```
feat: Add new feature (#123)
fix: Fix bug in module (#124)
```

### Problem: Email notification skipped

**Cause**: Previous job failed or dry run enabled

**Solution**:
1. Check if GitHub release job succeeded
2. Ensure dry run is disabled
3. Review workflow logs for conditional execution

## Best Practices

### 1. Use Conventional Commits

Follow conventional commit format for better release notes:

```bash
# Features
git commit -m "feat: Add email notification system (#42)"

# Bug fixes
git commit -m "fix: Resolve checksum generation issue (#43)"

# Documentation
git commit -m "docs: Update release workflow guide (#44)"

# Chores
git commit -m "chore: Update dependencies"
```

### 2. Always Reference PRs

Include PR numbers in commit messages:

```bash
git commit -m "feat: Add feature (#123)"
```

This automatically creates clickable links in release notes.

### 3. Use Separate Email for CI/CD

Create a dedicated email for automated notifications:
- `ci@yourcompany.com`
- `releases@yourcompany.com`
- `noreply-ci@yourcompany.com`

### 4. Test Before Production

Always test with dry run first:
1. Configure secrets
2. Run workflow with dry run enabled
3. Verify logs show email would be sent
4. Do actual release

### 5. Monitor Email Delivery

- Set up email forwarding rules
- Create filters to organize release notifications
- Monitor spam folder initially
- Whitelist sender address

### 6. Keep Secrets Secure

- Never commit secrets to repository
- Use GitHub Secrets for sensitive data
- Rotate SMTP passwords periodically
- Use app-specific passwords (not account passwords)

## Email Provider Comparison

| Provider | Free Tier | Ease of Setup | Reliability | Best For |
|----------|-----------|---------------|-------------|----------|
| **Gmail** | 100/day | Easy (2FA + App Password) | High | Personal/Small Teams |
| **SendGrid** | 100/day | Medium (API Key) | Very High | Production |
| **Amazon SES** | 62,000/month (free tier) | Medium (AWS Setup) | Very High | AWS Users |
| **Mailgun** | 5,000/month | Easy (API Key) | High | Startups |
| **Microsoft 365** | Included with subscription | Easy | High | Enterprise/Office Users |

## Security Considerations

### 1. Use App-Specific Passwords

Never use your main account password. Always create app-specific passwords.

### 2. Limit Permissions

Grant minimum required permissions to SMTP credentials.

### 3. Rotate Credentials

Rotate SMTP passwords every 90 days for security.

### 4. Monitor Usage

Check SMTP provider logs for unusual activity.

### 5. Use TLS/SSL

Always use encrypted SMTP connections:
- **Port 587 (STARTTLS)**: Don't set `secure: true` - encryption is handled via STARTTLS upgrade
- **Port 465 (SSL/TLS)**: Set `secure: true` for direct SSL/TLS connection

## Advanced Configuration

### Add Slack Integration

Combine email with Slack notifications:

```yaml
- name: Send Slack notification
  uses: slackapi/slack-github-action@v1
  with:
    channel-id: 'releases'
    slack-message: "🚀 New release: v${{ needs.preflight.outputs.version }}"
  env:
    SLACK_BOT_TOKEN: ${{ secrets.SLACK_BOT_TOKEN }}
```

### Add Discord Webhook

Send notifications to Discord:

```yaml
- name: Discord notification
  uses: Ilshidur/action-discord@master
  env:
    DISCORD_WEBHOOK: ${{ secrets.DISCORD_WEBHOOK }}
  with:
    args: '🚀 Bastion v${{ needs.preflight.outputs.version }} released!'
```

### Add Microsoft Teams

Send notifications to Teams:

```yaml
- name: Teams notification
  uses: dhollerbach/actions.teams@v1
  if: always()
  with:
    webhook_url: ${{ secrets.TEAMS_WEBHOOK_URL }}
    title: "Release v${{ needs.preflight.outputs.version }}"
```

## FAQ

**Q: Can I send to multiple emails?**
A: Yes, use comma-separated values in `RELEASE_NOTIFICATION_EMAIL`:
```
team@example.com, manager@example.com, releases@example.com
```

**Q: What if my company blocks Gmail?**
A: Use your company's SMTP server or a business email service like SendGrid, Amazon SES, or Microsoft 365.

**Q: How do I test without sending real emails?**
A: Use a test email service like [Mailtrap](https://mailtrap.io/) or [MailHog](https://github.com/mailhog/MailHog) for testing.

**Q: Can I disable email notifications temporarily?**
A: Yes, use the dry run option when manually triggering the workflow.

**Q: How do I add my company logo?**
A: Host your logo online and add to the HTML template:
```html
<img src="https://yourcompany.com/logo.png" alt="Logo" style="max-width: 200px;">
```

**Q: Can I send different emails based on version type?**
A: Yes, add conditional logic in the workflow:
```yaml
- name: Determine email template
  run: |
    if [[ "$VERSION" == *"RC"* ]]; then
      TEMPLATE="rc-email.html"
    else
      TEMPLATE="release-email.html"
    fi
```

## Support

For issues with email notifications:
1. Check workflow logs in GitHub Actions
2. Verify SMTP credentials in a test email client
3. Review this documentation
4. Create an issue on GitHub with workflow run URL
5. Email: it.dodogeny@gmail.com

---

**Last Updated**: 2025-12-18
**Workflow Version**: 2.0 (with Email Notifications)
**Maintained By**: Bastion Maven Plugin Team
