# GitHub Actions Workflow Setup

## Nightly Build Configuration

The nightly build workflow (`nightly-build.yml`) requires email notification credentials to be configured as GitHub Secrets.

### Required GitHub Secrets

To enable email notifications, you need to add the following secrets to your GitHub repository:

1. **MAIL_USERNAME**: Your email address (e.g., your Gmail address)
2. **MAIL_PASSWORD**: An app-specific password for your email account

### Setting up Gmail for Notifications

If using Gmail, you'll need to create an **App Password**:

1. Go to your Google Account settings: https://myaccount.google.com/
2. Navigate to **Security** → **2-Step Verification** (enable if not already enabled)
3. Scroll down to **App passwords**
4. Create a new app password for "Mail"
5. Copy the generated 16-character password

### Adding Secrets to GitHub

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add the following secrets:
   - Name: `MAIL_USERNAME`, Value: your email address
   - Name: `MAIL_PASSWORD`, Value: your app-specific password

### Alternative Email Providers

If not using Gmail, modify the `server_address` and `server_port` in the workflow file:

- **Gmail**: `smtp.gmail.com:587`
- **Outlook/Hotmail**: `smtp-mail.outlook.com:587`
- **Yahoo**: `smtp.mail.yahoo.com:587`
- **Custom SMTP**: Update with your provider's SMTP settings

### Testing the Workflow

You can manually trigger the workflow to test it:

1. Go to **Actions** tab in your GitHub repository
2. Select **Nightly Build and Test** workflow
3. Click **Run workflow** button
4. Select the branch and click **Run workflow**

### Schedule

The workflow runs automatically every night at **00:00 UTC (midnight)**.

### What Gets Tested

1. **Compilation**: `mvn clean compile` - Compiles all modules
2. **Tests**: `mvn test` - Runs all unit tests across all modules
3. **Email on Failure**: Sends notification to `dil.neemuth@gmail.com` if any step fails
4. **Test Reports**: Uploads test reports as artifacts for 30 days if tests fail
