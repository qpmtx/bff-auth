# NPM Token Setup for Automated Publishing

This document explains how to set up the NPM_TOKEN secret for automated publishing to npm.

## 🔑 Creating an NPM Access Token

1. **Login to npm**:

   ```bash

   npm login
   ```

2. **Create an access token**:
   - Go to [npmjs.com](https://www.npmjs.com) and login
   - Navigate to **Access Tokens** in your profile settings
   - Click **Generate New Token**
   - Select **Automation** type for CI/CD usage
   - Copy the generated token (starts with `npm_`)

## 🔒 Adding Token to GitHub Secrets

1. **Go to your GitHub repository**
2. **Navigate to Settings** → **Secrets and variables** → **Actions**
3. **Click "New repository secret"**
4. **Set the secret**:
   - **Name**: `NPM_TOKEN`
   - **Value**: Your npm access token (e.g., `npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`)
5. **Click "Add secret"**

## ✅ Verification

The release workflow will:

1. **Authenticate with npm** using the token
2. **Verify authentication** with `npm whoami`
3. **Publish the package** with public access
4. **Verify publication** by checking the published version

## 🛡️ Security Notes

- **Never commit** the NPM_TOKEN to your repository
- **Use automation tokens** for CI/CD (not publish tokens)
- **Rotate tokens regularly** for security
- **Limit token scope** to only necessary packages

## 🔧 Token Permissions

The NPM_TOKEN should have:

- ✅ **Publish** permission for `@qpmtx/bff-auth`
- ✅ **Read** permission for verification
- ❌ **No additional scopes** needed

## 🚀 Workflow Trigger

The release workflow triggers when:

- A **pull request is merged** to the `main` branch
- The **commit message** indicates a PR merge
- **Version is bumped** based on PR labels or title

## 📦 Package Publishing

The workflow will:

1. **Bump version** (patch/minor/major)
2. **Build the package**
3. **Authenticate with npm**
4. **Publish with public access**
5. **Create GitHub release**
6. **Update changelog**

## 🐛 Troubleshooting

### Authentication Failed

- Verify `NPM_TOKEN` secret is set correctly
- Check token hasn't expired
- Ensure token has publish permissions

### Package Already Exists

- Check if version was already published
- Verify version bump occurred correctly
- Look for duplicate publish attempts

### Permission Denied

- Verify token has access to `@qpmtx` scope
- Check if you're a maintainer of the package
- Ensure token has publish permissions

## 📞 Support

If you encounter issues:

1. Check the workflow logs for detailed error messages
2. Verify npm token permissions
3. Contact repository maintainers for help
