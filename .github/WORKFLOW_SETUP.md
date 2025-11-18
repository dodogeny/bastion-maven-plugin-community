# GitHub Actions Workflow Setup

## Nightly Build Configuration

The nightly build workflow (`nightly-build.yml`) uses GitHub's built-in notification system - **no secrets required!**

### How Notifications Work

When the nightly build fails, the workflow automatically:
1. **Creates a GitHub Issue** with build failure details
2. **GitHub sends email notifications** to:
   - Repository watchers
   - Users mentioned in the issue (@dodogeny)
   - Anyone subscribed to repository notifications

### Enable Email Notifications

To receive email notifications when builds fail:

1. **Watch the Repository**:
   - Go to your repository on GitHub
   - Click the **Watch** button (top right)
   - Select **All Activity** or **Custom** → Check **Issues**

2. **Configure Notification Settings**:
   - Go to https://github.com/settings/notifications
   - Under "Email notification preferences":
     - Ensure "Issues" is enabled
     - Set your preferred email address
   - Under "Subscriptions":
     - Choose "Email" for participating or watching

3. **Verify Email Address**:
   - Ensure `dil.neemuth@gmail.com` is verified in your GitHub account
   - Go to https://github.com/settings/emails to check

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
3. **Issue Creation on Failure**: Creates a GitHub issue with failure details and mentions @dodogeny
4. **Test Reports**: Uploads test reports as artifacts for 30 days if tests fail

### Issue Labels

Failed builds create issues with these labels:
- `bug` - Marks the issue as a bug
- `nightly-build-failure` - Identifies it as a nightly build failure
- `automated` - Shows it was created automatically

### Cleaning Up

After fixing a build failure:
1. Verify the next nightly build succeeds
2. Close the issue manually or reference it in your commit message with "Fixes #X"
