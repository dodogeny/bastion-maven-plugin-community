#!/bin/bash

# Bastion Maven Plugin Uninstallation Script
# Version: ${project.version}

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "🗑️  Bastion Maven Plugin Uninstaller v${project.version}"
    echo "========================================================"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

confirm_uninstall() {
    echo
    print_warning "This will remove Bastion Maven Plugin from your local Maven repository."
    print_info "Your project configurations (pom.xml) will not be modified."
    echo
    
    while true; do
        read -p "Do you want to continue? (y/N): " yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) echo "Uninstallation cancelled."; exit 0;;
            "" ) echo "Uninstallation cancelled."; exit 0;;
            * ) echo "Please answer yes or no.";;
        esac
    done
    
    echo
}

remove_from_local_repository() {
    print_info "Removing Bastion Maven Plugin from local repository..."
    
    # Get Maven local repository path
    LOCAL_REPO=$(mvn help:evaluate -Dexpression=settings.localRepository -q -DforceStdout 2>/dev/null || echo "$HOME/.m2/repository")
    
    # Remove Bastion artifacts
    BASTION_REPO_DIR="$LOCAL_REPO/mu/dodogeny"
    
    if [ -d "$BASTION_REPO_DIR" ]; then
        # List what will be removed
        print_info "The following artifacts will be removed:"
        find "$BASTION_REPO_DIR" -name "bastion-*" -type d | sed 's/^/  - /'
        echo
        
        # Remove all Bastion-related artifacts
        find "$BASTION_REPO_DIR" -name "bastion-*" -type d -exec rm -rf {} + 2>/dev/null || true
        
        # Remove parent directory if empty
        if [ -d "$BASTION_REPO_DIR" ] && [ -z "$(ls -A "$BASTION_REPO_DIR" 2>/dev/null)" ]; then
            rmdir "$BASTION_REPO_DIR"
            print_success "Removed empty parent directory"
        fi
        
        print_success "Removed from local repository: $LOCAL_REPO"
    else
        print_warning "Bastion artifacts not found in local repository"
    fi
}

clean_maven_cache() {
    print_info "Cleaning Maven plugin cache..."
    
    # Remove plugin registry cache
    PLUGIN_REGISTRY="$HOME/.m2/repository/.meta/maven-metadata-central.xml"
    if [ -f "$PLUGIN_REGISTRY" ]; then
        # Remove Bastion entries from plugin registry
        sed -i.bak '/mu\.dodogeny.*bastion/d' "$PLUGIN_REGISTRY" 2>/dev/null || true
        print_success "Cleaned plugin registry"
    fi
    
    # Clear Maven plugin cache
    mvn dependency:purge-local-repository -DmanualInclude=mu.dodogeny:bastion-maven-plugin >/dev/null 2>&1 || true
}

remove_configuration_examples() {
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    BASTION_HOME="$(dirname "$SCRIPT_DIR")"
    
    if [ -d "$BASTION_HOME/examples" ]; then
        print_info "Removing configuration examples..."
        rm -rf "$BASTION_HOME/examples"
        print_success "Removed example configurations"
    fi
}

verify_removal() {
    print_info "Verifying removal..."
    
    if mvn help:describe -Dplugin=mu.dodogeny:bastion-maven-plugin >/dev/null 2>&1; then
        print_warning "Plugin may still be available (possibly from remote repository)"
        print_info "This is normal if the plugin was downloaded from Maven Central"
    else
        print_success "Plugin successfully removed from local environment"
    fi
}

show_cleanup_instructions() {
    echo
    print_info "Manual cleanup steps (if needed):"
    echo
    echo "1. Remove plugin from your project's pom.xml:"
    echo "   - Delete the <plugin> block with groupId 'mu.dodogeny' and artifactId 'bastion-maven-plugin'"
    echo
    echo "2. Clean your project:"
    echo "   mvn clean"
    echo
    echo "3. Remove generated reports (optional):"
    echo "   rm -rf target/bastion-reports/"
    echo
    print_info "License files (if any) are not automatically removed for security."
    print_info "Please manually remove them from secure locations."
}

main() {
    print_header
    
    # Check if Maven is available
    if ! command -v mvn >/dev/null 2>&1; then
        print_error "Maven not found. Cannot proceed with uninstallation."
        exit 1
    fi
    
    confirm_uninstall
    remove_from_local_repository
    clean_maven_cache
    remove_configuration_examples
    verify_removal
    show_cleanup_instructions
    
    echo
    echo -e "${GREEN}🎉 Uninstallation completed!${NC}"
    echo
    print_info "Thank you for using Bastion Maven Plugin."
    print_info "If you encounter any issues, please visit: https://github.com/dodogeny/bastion-maven-plugin/issues"
}

# Run main function
main "$@"