#!/bin/bash
# =============================================================================
# CyAudit 3.5 Installer Build Script
# =============================================================================
# Builds the Windows installer using Docker (no Windows machine required)
#
# Usage:
#   ./build.sh                  # Build standard installer
#   ./build.sh --protected      # Build protected (Clean) installer
#   ./build.sh --all            # Build both installers
#   ./build.sh --clean          # Clean output and rebuild
#   ./build.sh --help           # Show help
#
# Requirements:
#   - Docker installed and running
#   - Internet access to pull Docker image (first run only)
#   - For protected build: Run Build-CyAuditExe.ps1 on Windows first
#
# =============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISS_STANDARD="CyAudit_Setup.iss"
ISS_PROTECTED="CyAudit_Setup_Clean.iss"
OUTPUT_DIR="Output"
BUILD_DIR="CyAudit_3.5/Build"
DOCKER_IMAGE="amake/innosetup"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo ""
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE}  CyAudit 3.5 Installer Builder${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

show_help() {
    echo "CyAudit 3.5 Installer Build Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Build Options:"
    echo "  (default)     Build standard installer (PowerShell scripts)"
    echo "  --protected   Build protected installer (compiled EXEs)"
    echo "  --all         Build both standard and protected installers"
    echo ""
    echo "Other Options:"
    echo "  --clean       Clean output directory before building"
    echo "  --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                      # Build standard installer"
    echo "  $0 --protected          # Build protected installer"
    echo "  $0 --all --clean        # Clean and build both"
    echo ""
    echo "Output files:"
    echo "  Standard:  ${OUTPUT_DIR}/CyAudit_3.5_Setup.exe"
    echo "  Protected: ${OUTPUT_DIR}/CyAudit_3.5_Setup_Clean.exe"
    echo ""
    echo "Note: Protected build requires running Build-CyAuditExe.ps1 on Windows first"
    echo "      to compile PowerShell scripts to EXE files."
    echo ""
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        echo ""
        echo "Please install Docker:"
        echo "  - macOS: https://docs.docker.com/desktop/mac/install/"
        echo "  - Linux: https://docs.docker.com/engine/install/"
        echo "  - Windows: https://docs.docker.com/desktop/windows/install/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        echo ""
        echo "Please start Docker and try again."
        exit 1
    fi

    print_success "Docker is available"
}

check_files() {
    local build_type=$1

    if [ "$build_type" = "standard" ] || [ "$build_type" = "all" ]; then
        if [ ! -f "${SCRIPT_DIR}/${ISS_STANDARD}" ]; then
            print_error "Inno Setup script not found: ${ISS_STANDARD}"
            exit 1
        fi
    fi

    if [ "$build_type" = "protected" ] || [ "$build_type" = "all" ]; then
        if [ ! -f "${SCRIPT_DIR}/${ISS_PROTECTED}" ]; then
            print_error "Inno Setup script not found: ${ISS_PROTECTED}"
            exit 1
        fi
    fi

    if [ ! -d "${SCRIPT_DIR}/CyAudit_3.5" ]; then
        print_error "CyAudit_3.5 directory not found"
        exit 1
    fi

    print_success "Required files found"
}

check_protected_prereqs() {
    # Check if compiled EXEs exist for protected build
    local required_exes=(
        "CyAudit_Opus_V3.5.exe"
        "Run-CyAuditPipeline.exe"
        "Run-CyAuditElevated.exe"
        "Transform-CyAuditForSplunk.exe"
        "Test-SplunkTransformation.exe"
        "Upload-ToSplunkCloud.exe"
    )

    local missing=()
    for exe in "${required_exes[@]}"; do
        if [ ! -f "${SCRIPT_DIR}/${BUILD_DIR}/${exe}" ]; then
            missing+=("$exe")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        print_error "Protected build requires compiled EXE files"
        echo ""
        echo "Missing files in ${BUILD_DIR}/:"
        for exe in "${missing[@]}"; do
            echo "  - ${exe}"
        done
        echo ""
        echo "To create these files:"
        echo "  1. Copy this directory to a Windows machine"
        echo "  2. Run: powershell -ExecutionPolicy Bypass -File Build-CyAuditExe.ps1"
        echo "  3. Copy the Build/ directory back and run this script again"
        echo ""
        exit 1
    fi

    print_success "Compiled EXE files found"
}

clean_output() {
    if [ -d "${SCRIPT_DIR}/${OUTPUT_DIR}" ]; then
        print_info "Cleaning output directory..."
        rm -rf "${SCRIPT_DIR}/${OUTPUT_DIR}"
    fi
}

pull_docker_image() {
    print_info "Checking Docker image: ${DOCKER_IMAGE}"

    if ! docker image inspect "${DOCKER_IMAGE}" &> /dev/null; then
        print_info "Pulling Docker image (this may take a few minutes on first run)..."
        docker pull "${DOCKER_IMAGE}"
    fi

    print_success "Docker image ready"
}

build_installer() {
    local iss_file=$1
    local output_name=$2
    local build_type=$3

    print_info "Building ${build_type} installer..."
    echo ""

    # Create output directory
    mkdir -p "${SCRIPT_DIR}/${OUTPUT_DIR}"

    # Run Inno Setup compiler in Docker
    docker run --rm \
        -v "${SCRIPT_DIR}:/work" \
        "${DOCKER_IMAGE}" \
        "${iss_file}"

    # Check if build succeeded
    if [ -f "${SCRIPT_DIR}/${OUTPUT_DIR}/${output_name}" ]; then
        echo ""
        print_success "${build_type} build completed!"
        echo ""
        echo -e "${GREEN}Output:${NC} ${SCRIPT_DIR}/${OUTPUT_DIR}/${output_name}"

        # Show file size
        SIZE=$(du -h "${SCRIPT_DIR}/${OUTPUT_DIR}/${output_name}" | cut -f1)
        echo -e "${GREEN}Size:${NC}   ${SIZE}"
        echo ""
    else
        print_error "Build failed - output file not created"
        exit 1
    fi
}

# Main script
main() {
    print_header

    # Parse arguments
    CLEAN=false
    BUILD_STANDARD=false
    BUILD_PROTECTED=false

    # Default to standard if no build type specified
    if [ $# -eq 0 ]; then
        BUILD_STANDARD=true
    fi

    for arg in "$@"; do
        case $arg in
            --clean)
                CLEAN=true
                ;;
            --protected)
                BUILD_PROTECTED=true
                ;;
            --all)
                BUILD_STANDARD=true
                BUILD_PROTECTED=true
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                # If only --clean is passed, default to standard build
                if [ "$arg" != "--clean" ]; then
                    print_error "Unknown option: $arg"
                    show_help
                    exit 1
                fi
                ;;
        esac
    done

    # If only --clean was specified, default to standard
    if [ "$BUILD_STANDARD" = false ] && [ "$BUILD_PROTECTED" = false ]; then
        BUILD_STANDARD=true
    fi

    # Change to script directory
    cd "${SCRIPT_DIR}"

    # Pre-flight checks
    print_info "Running pre-flight checks..."
    check_docker

    # Determine build type for file checks
    if [ "$BUILD_STANDARD" = true ] && [ "$BUILD_PROTECTED" = true ]; then
        check_files "all"
    elif [ "$BUILD_PROTECTED" = true ]; then
        check_files "protected"
    else
        check_files "standard"
    fi

    # Check protected prerequisites
    if [ "$BUILD_PROTECTED" = true ]; then
        check_protected_prereqs
    fi

    # Clean if requested
    if [ "$CLEAN" = true ]; then
        clean_output
    fi

    # Pull Docker image if needed
    pull_docker_image

    # Build standard installer
    if [ "$BUILD_STANDARD" = true ]; then
        build_installer "${ISS_STANDARD}" "CyAudit_3.5_Setup.exe" "Standard"
    fi

    # Build protected installer
    if [ "$BUILD_PROTECTED" = true ]; then
        build_installer "${ISS_PROTECTED}" "CyAudit_3.5_Setup_Clean.exe" "Protected"
    fi

    # Summary
    echo "============================================="
    echo "Build Summary"
    echo "============================================="
    if [ "$BUILD_STANDARD" = true ]; then
        echo "  Standard:  ${OUTPUT_DIR}/CyAudit_3.5_Setup.exe"
    fi
    if [ "$BUILD_PROTECTED" = true ]; then
        echo "  Protected: ${OUTPUT_DIR}/CyAudit_3.5_Setup_Clean.exe"
    fi
    echo ""
    echo "To test the installer:"
    echo "  1. Copy the .exe file to a Windows machine"
    echo "  2. Right-click and 'Run as administrator'"
    echo "  3. For silent install: <installer>.exe /VERYSILENT"
    echo ""
}

# Run main function
main "$@"
