#!/bin/bash

# SecHive Maven Plugin Installation Script
# Version: ${project.version}

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SECHIVE_HOME="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "🛡️  SecHive Maven Plugin Installer v${project.version}"
    echo "======================================================"
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

check_requirements() {
    print_info "Checking system requirements..."
    
    # Check Java
    if command -v java >/dev/null 2>&1; then
        JAVA_VERSION=$(java -version 2>&1 | grep -oP 'version "([0-9]+)' | grep -oP '[0-9]+' | head -1)
        if [ "$JAVA_VERSION" -ge 8 ]; then
            print_success "Java $JAVA_VERSION detected"
        else
            print_error "Java 8 or higher required, found Java $JAVA_VERSION"
            exit 1
        fi
    else
        print_error "Java not found. Please install Java JDK 8 or higher"
        exit 1
    fi
    
    # Check Maven
    if command -v mvn >/dev/null 2>&1; then
        MVN_VERSION=$(mvn -version | grep "Apache Maven" | cut -d' ' -f3)
        print_success "Maven $MVN_VERSION detected"
    else
        print_error "Maven not found. Please install Apache Maven 3.6.0 or higher"
        exit 1
    fi
    
    echo
}

install_to_local_repository() {
    print_info "Installing SecHive Maven Plugin to local repository..."
    
    # Get Maven local repository path
    LOCAL_REPO=$(mvn help:evaluate -Dexpression=settings.localRepository -q -DforceStdout 2>/dev/null || echo "$HOME/.m2/repository")
    
    # Create directory structure
    SECHIVE_REPO_DIR="$LOCAL_REPO/io/github/dodogeny/sechive-maven-plugin/${project.version}"
    mkdir -p "$SECHIVE_REPO_DIR"
    
    # Copy main plugin JAR
    if [ -f "$SECHIVE_HOME/lib/sechive-maven-plugin-${project.version}.jar" ]; then
        cp "$SECHIVE_HOME/lib/sechive-maven-plugin-${project.version}.jar" "$SECHIVE_REPO_DIR/"
        print_success "Copied plugin JAR"
    else
        print_error "Plugin JAR not found in $SECHIVE_HOME/lib/"
        exit 1
    fi
    
    # Copy dependency JARs
    SECHIVE_DEPS_DIR="$LOCAL_REPO/io/github/dodogeny"
    mkdir -p "$SECHIVE_DEPS_DIR"
    
    for jar in "$SECHIVE_HOME"/lib/sechive-*.jar; do
        if [ -f "$jar" ]; then
            # Extract artifactId from filename
            ARTIFACT=$(basename "$jar" | sed 's/-[0-9].*//')
            ARTIFACT_DIR="$SECHIVE_DEPS_DIR/$ARTIFACT/${project.version}"
            mkdir -p "$ARTIFACT_DIR"
            cp "$jar" "$ARTIFACT_DIR/"
        fi
    done
    
    print_success "Installed to local repository: $LOCAL_REPO"
}

create_example_pom() {
    print_info "Creating example project configuration..."
    
    EXAMPLE_DIR="$SECHIVE_HOME/examples/quick-start"
    mkdir -p "$EXAMPLE_DIR"
    
    cat > "$EXAMPLE_DIR/pom-snippet.xml" << EOF
<!-- Add this plugin to your project's pom.xml -->
<plugin>
    <groupId>io.github.dodogeny</groupId>
    <artifactId>sechive-maven-plugin</artifactId>
    <version>${project.version}</version>
    <executions>
        <execution>
            <goals>
                <goal>scan</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
        <!-- Basic configuration -->
        <severityThreshold>MEDIUM</severityThreshold>
        <reportFormats>HTML,JSON</reportFormats>
        <failOnError>true</failOnError>
        
        <!-- For commercial edition -->
        <!-- <licensePath>/path/to/sechive-license.enc</licensePath> -->
    </configuration>
</plugin>
EOF
    
    print_success "Created example configuration in $EXAMPLE_DIR"
}

create_verification_script() {
    cat > "$SECHIVE_HOME/bin/verify-installation.sh" << 'EOF'
#!/bin/bash

echo "🔍 Verifying SecHive Maven Plugin installation..."

# Check if plugin is available
if mvn help:describe -Dplugin=io.github.dodogeny:sechive-maven-plugin >/dev/null 2>&1; then
    echo "✅ Plugin found in repository"

    # Get plugin version
    PLUGIN_INFO=$(mvn help:describe -Dplugin=io.github.dodogeny:sechive-maven-plugin -Ddetail=false 2>/dev/null)
    echo "$PLUGIN_INFO" | grep -E "(Name|Version|Description)"

    echo ""
    echo "🚀 Ready to scan! Try:"
    echo "   mvn io.github.dodogeny:sechive-maven-plugin:${project.version}:scan"
    echo ""
    echo "📚 Documentation: $SECHIVE_HOME/docs/"
    echo "💡 Examples: $SECHIVE_HOME/examples/"
else
    echo "❌ Plugin not found. Installation may have failed."
    echo "   Try running: $SECHIVE_HOME/bin/install.sh"
    exit 1
fi
EOF
    
    chmod +x "$SECHIVE_HOME/bin/verify-installation.sh"
}

main() {
    print_header
    
    print_info "Installation directory: $SECHIVE_HOME"
    echo
    
    check_requirements
    install_to_local_repository
    create_example_pom
    create_verification_script
    
    echo
    echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
    echo
    print_info "Next steps:"
    echo "  1. Verify installation: $SECHIVE_HOME/bin/verify-installation.sh"
    echo "  2. Add plugin to your project using: $SECHIVE_HOME/examples/quick-start/pom-snippet.xml"
    echo "  3. Run your first scan: mvn sechive:scan"
    echo
    print_info "Documentation: $SECHIVE_HOME/docs/"
    print_info "Examples: $SECHIVE_HOME/examples/"
    echo
    print_info "For commercial features, visit: https://sechive-plugin.lemonsqueezy.com"
    
    # Run verification
    if [ -x "$SECHIVE_HOME/bin/verify-installation.sh" ]; then
        echo
        "$SECHIVE_HOME/bin/verify-installation.sh"
    fi
}

# Run main function
main "$@"