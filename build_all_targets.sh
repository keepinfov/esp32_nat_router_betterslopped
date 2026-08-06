#!/bin/bash
#
# ESP32 NAT Router — build and size-check one target, several, or all of them.
#
#   ./build_all_targets.sh esp32c3          one target
#   ./build_all_targets.sh esp32c3 wt32_eth01
#   ./build_all_targets.sh                  everything in BUILD_ORDER
#   ./build_all_targets.sh --clean esp32c3  full rebuild
#   ./build_all_targets.sh --save           also refresh firmware_*/
#
# Leaving optional subsystems out, when flash is tight:
#
#   ./build_all_targets.sh --without mqtt esp32c3
#   ./build_all_targets.sh --without mqtt,oled,pcap esp32c3
#   ./build_all_targets.sh --minimal esp32c3          all of them off
#   ./build_all_targets.sh --features                 what they cost
#
# Builds are incremental and leave the repository untouched unless --save is
# given: checking that something still compiles should not rewrite nine
# megabytes of tracked binaries. Changing the feature set is the exception —
# it forces a reconfigure, because ESP-IDF treats an existing sdkconfig as the
# source of truth and would otherwise ignore the request.
#
# Requires a sourced ESP-IDF environment: . $IDF_PATH/export.sh

set -e  # Exit on any error

DO_CLEAN=false
DO_SAVE=false
DISABLED_FEATURES=()

# Optional subsystems, by the name you type. Each is a Kconfig option that
# defaults to y; turning one off compiles its component to nothing. The sizes
# are measured on the ESP32-C3, each by building with that one option off.
declare -A FEATURE_OPTION=(
    ["mqtt"]="CONFIG_MQTT_HOMEASSISTANT"
    ["oled"]="CONFIG_OLED_DISPLAY"
    ["console"]="CONFIG_REMOTE_CONSOLE"
    ["pcap"]="CONFIG_PCAP_CAPTURE"
    ["syslog"]="CONFIG_SYSLOG_CLIENT"
)

declare -A FEATURE_DESC=(
    ["mqtt"]="MQTT / Home Assistant telemetry     57.3 KB"
    ["oled"]="SSD1306 status display (C3/S3)      18.8 KB"
    ["console"]="Remote console over TCP              5.5 KB"
    ["pcap"]="Packet capture to Wireshark          4.7 KB"
    ["syslog"]="Remote syslog over UDP               3.1 KB"
)

# The order they are listed in, largest first.
FEATURE_ORDER=("mqtt" "oled" "console" "pcap" "syslog")

# Build targets in order
BUILD_ORDER=("esp32" "wt32_eth01" "esp32_poe_iso" "esp32s3" "esp32c5" "esp32c6" "esp32c3")

# Target descriptions
declare -A TARGET_DESC=(
    ["esp32"]="ESP32 (Original)"
    ["esp32s3"]="ESP32-S3"
    ["esp32c6"]="ESP32-C6"
    ["esp32c3"]="ESP32-C3"
    ["esp32c5"]="ESP32-C5"
    ["wt32_eth01"]="WT32-ETH01 (Ethernet)"
    ["esp32_poe_iso"]="Olimex ESP32-POE-ISO (Ethernet)"
)

# IDF chip target for each build target
declare -A TARGET_CHIP=(
    ["esp32"]="esp32"
    ["esp32s3"]="esp32s3"
    ["esp32c6"]="esp32c6"
    ["esp32c3"]="esp32c3"
    ["esp32c5"]="esp32c5"
    ["wt32_eth01"]="esp32"
    ["esp32_poe_iso"]="esp32"
)

# Extra sdkconfig defaults (semicolon-separated).
# Every target needs an entry: without one idf.py falls back to plain
# sdkconfig.defaults and silently drops the per-target overrides, which is how
# the published C5 binary ended up without its reduced log level.
declare -A TARGET_SDKCONFIG=(
    ["esp32"]="sdkconfig.defaults;sdkconfig.defaults.esp32"
    ["esp32s3"]="sdkconfig.defaults;sdkconfig.defaults.esp32s3"
    ["esp32c6"]="sdkconfig.defaults;sdkconfig.defaults.esp32c6"
    ["esp32c3"]="sdkconfig.defaults;sdkconfig.defaults.esp32c3"
    ["esp32c5"]="sdkconfig.defaults;sdkconfig.defaults.esp32c5"
    ["wt32_eth01"]="sdkconfig.defaults;sdkconfig.defaults.eth_common;sdkconfig.defaults.wt32_eth01"
    ["esp32_poe_iso"]="sdkconfig.defaults;sdkconfig.defaults.eth_common;sdkconfig.defaults.esp32_poe_iso"
)

# Per-target build directory and sdkconfig, so a stale config from the previous
# target can never leak into the next one.
declare -A TARGET_BUILD_DIR=(
    ["esp32"]="build_esp32"
    ["esp32s3"]="build_esp32s3"
    ["esp32c6"]="build_esp32c6"
    ["esp32c3"]="build_esp32c3"
    ["esp32c5"]="build_esp32c5"
    ["wt32_eth01"]="build_eth"
    ["esp32_poe_iso"]="build_poe_iso"
)

declare -A TARGET_SDKCONFIG_FILE=(
    ["esp32"]="sdkconfig.esp32"
    ["esp32s3"]="sdkconfig.esp32s3"
    ["esp32c6"]="sdkconfig.esp32c6"
    ["esp32c3"]="sdkconfig.esp32c3"
    ["esp32c5"]="sdkconfig.esp32c5"
    ["wt32_eth01"]="sdkconfig.eth"
    ["esp32_poe_iso"]="sdkconfig.poe_iso"
)

# Fail the build when the app no longer leaves room in its OTA slot.
# ota_0 is 1536 KiB (partitions_example.csv).
OTA_MAX_PERCENT=95

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to build for specific target
build_target() {
    local target=$1
    local description=$2
    local chip="${TARGET_CHIP[$target]}"
    local sdkconfig="${TARGET_SDKCONFIG[$target]}"
    local build_dir="${TARGET_BUILD_DIR[$target]}"
    local sdkconfig_file="${TARGET_SDKCONFIG_FILE[$target]}"
    local build_args=()

    print_status "Building for $description ($target)..."

    # Use custom build directory if specified
    if [ -n "$build_dir" ]; then
        build_args+=("-B" "$build_dir")
    fi

    # Use custom sdkconfig file if specified (avoids conflicts with shared sdkconfig)
    if [ -n "$sdkconfig_file" ]; then
        build_args+=("-D" "SDKCONFIG=$sdkconfig_file")
    fi

    # Anything named on --without goes on the end of the defaults chain, where
    # it wins over the shared and per-target files.
    features_fragment "$target"
    if [ -n "$FEATURES_FILE" ]; then
        sdkconfig="$sdkconfig;$FEATURES_FILE"
    fi

    # Use custom sdkconfig defaults if specified
    if [ -n "$sdkconfig" ]; then
        build_args+=("-D" "SDKCONFIG_DEFAULTS=$sdkconfig")
    fi

    # set-target implies fullclean — it wipes the build directory before
    # reconfiguring. Running it unconditionally, as this script used to, made
    # every build a full rebuild no matter what. It is only needed when there
    # is no configured build tree yet, or when the tree is configured for a
    # different chip.
    local configured=""
    if [ -f "$sdkconfig_file" ]; then
        configured=$(sed -n 's/^CONFIG_IDF_TARGET="\(.*\)"$/\1/p' "$sdkconfig_file")
    fi

    # A changed feature set is the third reason to reconfigure: set-target
    # clears sdkconfig, which is the only way a defaults file can change a
    # value that is already in it.
    if [ "$DO_CLEAN" = true ] || [ ! -d "$build_dir" ] || \
       [ "$configured" != "$chip" ] || [ "$FEATURES_CHANGED" = true ]; then
        if [ "$FEATURES_CHANGED" = true ] && [ -d "$build_dir" ]; then
            print_status "Feature set changed — reconfiguring from defaults"
        fi
        # Goes quiet for a while at "Building ESP-IDF components for target ..."
        # while dependencies are resolved; say so rather than leaving a silent
        # terminal that looks hung.
        print_status "Configuring for $chip (resolving dependencies, may pause here)..."
        idf.py "${build_args[@]}" set-target "$chip"
    else
        print_status "Reusing $build_dir (configured for $chip)"
    fi

    # Build project
    print_status "Starting compilation for $target..."
    if idf.py "${build_args[@]}" build; then
        if ! check_ota_headroom "$target"; then
            return 1
        fi
        # Only on request: this overwrites tracked binaries in firmware_*/,
        # which a plain "does it still build" run has no business doing.
        if [ "$DO_SAVE" = true ]; then
            save_binary_artifacts "$target" "$description"
        fi
        print_success "Build completed successfully for $target"
        return 0
    else
        print_error "Build failed for $target"
        return 1
    fi
}

# Refuse to publish a build that has nearly filled its OTA slot. Without this
# the C3 and C5 images crept to over 99% of ota_0 unnoticed. Shares the check
# with CI so the two cannot drift apart.
check_ota_headroom() {
    local target=$1
    local build_dir="${TARGET_BUILD_DIR[$target]:-build}"

    if python3 "$SCRIPT_DIR/tools/check_app_size.py" "$build_dir" \
            --name "$target" --limit "$OTA_MAX_PERCENT" \
            --baseline "firmware_$target/esp32_nat_router.bin"; then
        return 0
    fi
    print_error "Free flash before publishing — see 'idf.py size-components'."
    return 1
}

# Function to save binary artifacts to separate directory
save_binary_artifacts() {
    local target=$1
    local description=$2
    local artifacts_dir="firmware_$target"
    
    print_status "Saving binary artifacts to $artifacts_dir/..."

    # Create artifacts directory if it doesn't exist
    mkdir -p "$artifacts_dir"

    # Find and copy relevant binary files
    local build_dir="${TARGET_BUILD_DIR[$target]:-build}"
    local files_copied=0
    
    # Main firmware binary
    if [ -f "$build_dir/esp32_nat_router.bin" ]; then
        cp "$build_dir/esp32_nat_router.bin" "$artifacts_dir/"
        print_status "  ✓ Copied esp32_nat_router.bin"
        ((files_copied++))
    fi
    
    # Bootloader binary
    if [ -f "$build_dir/bootloader/bootloader.bin" ]; then
        cp "$build_dir/bootloader/bootloader.bin" "$artifacts_dir/"
        print_status "  ✓ Copied bootloader.bin"
        ((files_copied++))
    fi
    
    # Partition table
    if [ -f "$build_dir/partition_table/partition-table.bin" ]; then
        cp "$build_dir/partition_table/partition-table.bin" "$artifacts_dir/"
        print_status "  ✓ Copied partition-table.bin"
        ((files_copied++))
    fi

    # OTA data initial (required for OTA partition layout)
    if [ -f "$build_dir/ota_data_initial.bin" ]; then
        cp "$build_dir/ota_data_initial.bin" "$artifacts_dir/"
        print_status "  ✓ Copied ota_data_initial.bin"
        ((files_copied++))
    fi

    # Combined firmware (if available)
    if [ -f "$build_dir/esp32_nat_router-merged.bin" ]; then
        cp "$build_dir/esp32_nat_router-merged.bin" "$artifacts_dir/"
        print_status "  ✓ Copied esp32_nat_router-merged.bin"
        ((files_copied++))
    fi
    
    # Copy any other .bin files
    for bin_file in "$build_dir"/*.bin; do
        if [ -f "$bin_file" ]; then
            local filename=$(basename "$bin_file")
            if [ ! -f "$artifacts_dir/$filename" ]; then
                cp "$bin_file" "$artifacts_dir/"
                print_status "  ✓ Copied $filename"
                ((files_copied++))
            fi
        fi
    done
    
    # Create a version info file
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local git_hash=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    cat > "$artifacts_dir/build_info.txt" << EOF
ESP32 NAT Router Build Information
=================================
Target: $description ($target)
Build Time: $timestamp
Git Hash: $git_hash
Binary Files: $files_copied
Build Directory: $build_dir
EOF
    
    print_status "  ✓ Created build_info.txt"
    print_success "Saved $files_copied binary files to $artifacts_dir/"
}

# Function to check if idf.py is available
check_idf_env() {
    if ! command -v idf.py &> /dev/null; then
        print_error "idf.py not found. ESP-IDF environment not set up properly."
        print_error "Please source ESP-IDF export script first:"
        print_error "  source /path/to/esp-idf/export.sh"
        exit 1
    fi
}

usage() {
    # The header comment above is the help text; print it up to the first line
    # that is not a comment, so the two cannot drift apart.
    awk 'NR>2 && /^#/ { sub(/^# ?/, ""); print; next } NR>2 { exit }' "${BASH_SOURCE[0]}"
    echo "Targets: ${BUILD_ORDER[*]}"
    echo "Features (for --without): ${FEATURE_ORDER[*]}"
}

list_features() {
    echo "Optional subsystems — all built in by default, name them to --without:"
    echo
    for f in "${FEATURE_ORDER[@]}"; do
        printf '  %-9s %s\n' "$f" "${FEATURE_DESC[$f]}"
    done
    echo
    echo "  --minimal is all five, which frees 92.5 KB on the C3."
    echo "  Sizes measured there; each is a build with that one option off."
}

# Write the sdkconfig fragment that turns the requested features off, and say
# whether it differs from what this target was last configured with.
#
# ESP-IDF treats an existing sdkconfig as authoritative: a defaults file cannot
# override a value already in it. So a changed feature set has to go through
# set-target, which clears sdkconfig and regenerates it from the defaults
# chain. The stamp is what tells us the set changed.
features_fragment() {
    local target=$1
    local fragment="sdkconfig.${target}.features"
    local wanted=""

    for f in "${DISABLED_FEATURES[@]:-}"; do
        [ -n "$f" ] || continue
        wanted+="${FEATURE_OPTION[$f]}=n"$'\n'
    done

    FEATURES_CHANGED=false
    if [ -z "$wanted" ]; then
        # Nothing to disable. Drop a stale fragment so a previous --without
        # does not quietly persist into a plain run.
        if [ -f "$fragment" ]; then
            rm -f "$fragment"
            FEATURES_CHANGED=true
        fi
        FEATURES_FILE=""
        return
    fi

    if [ ! -f "$fragment" ] || [ "$(cat "$fragment")" != "$wanted" ]; then
        printf '%s' "$wanted" > "$fragment"
        FEATURES_CHANGED=true
    fi
    FEATURES_FILE="$fragment"
}

# Reads flags and target names; leaves SELECTED_TARGETS holding what to build.
parse_args() {
    SELECTED_TARGETS=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --clean) DO_CLEAN=true ;;
            --save)  DO_SAVE=true ;;
            --minimal) DISABLED_FEATURES=("${FEATURE_ORDER[@]}") ;;
            --without)
                shift
                [ $# -gt 0 ] || { print_error "--without needs a feature list"; list_features; exit 1; }
                # Comma-separated, so --without mqtt,oled reads naturally.
                IFS=',' read -ra _feats <<< "$1"
                for f in "${_feats[@]}"; do
                    if [ -z "${FEATURE_OPTION[$f]:-}" ]; then
                        print_error "Unknown feature: $f"
                        list_features
                        exit 1
                    fi
                    DISABLED_FEATURES+=("$f")
                done
                ;;
            --features) list_features; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [ -z "${TARGET_CHIP[$1]:-}" ]; then
                    print_error "Unknown target: $1"
                    print_error "Available: ${BUILD_ORDER[*]}"
                    exit 1
                fi
                SELECTED_TARGETS+=("$1")
                ;;
        esac
        shift
    done

    if [ ${#SELECTED_TARGETS[@]} -eq 0 ]; then
        SELECTED_TARGETS=("${BUILD_ORDER[@]}")
    fi
}

# Main script execution
main() {
    parse_args "$@"

    print_status "ESP32 NAT Router Multi-Target Build Script"
    print_status "=========================================="

    # Check if ESP-IDF environment is set up
    check_idf_env

    cd "$SCRIPT_DIR"

    # ESP-IDF's component manager re-checks the manifest against Espressif's
    # registry on every configure. Once dependencies.lock and
    # managed_components/ exist there is nothing to fetch, but the check still
    # runs — and on a blocked or slow network it sits on a TCP timeout with no
    # output, which looks exactly like a hung build. Bounding the request makes
    # it give up in seconds and carry on offline. An explicit setting wins.
    if [ -f dependencies.lock ] && [ -d managed_components ]; then
        export IDF_COMPONENT_API_TIMEOUT="${IDF_COMPONENT_API_TIMEOUT:-10}"
    fi

    print_status "Working directory: $(pwd)"
    print_status "Targets: ${SELECTED_TARGETS[*]}"
    [ "$DO_SAVE" = true ] && print_warning "--save: firmware_*/ will be overwritten"
    if [ ${#DISABLED_FEATURES[@]} -gt 0 ]; then
        print_status "Leaving out: ${DISABLED_FEATURES[*]}"
    fi

    # Array to store failed targets
    FAILED_TARGETS=()

    # Build for each target
    for target in "${SELECTED_TARGETS[@]}"; do
        description="${TARGET_DESC[$target]}"
        echo ""
        print_status "=========================================="
        
        if ! build_target "$target" "$description"; then
            FAILED_TARGETS+=("$target")
        fi
        
        echo ""
    done
    
    # Final summary
    echo ""
    print_status "=========================================="
    print_status "Build Summary"
    print_status "=========================================="

    # Sizes of what was just built, next to the image currently published in
    # firmware_<target>/, so the run answers "what did this cost or save".
    for target in "${SELECTED_TARGETS[@]}"; do
        build_dir="${TARGET_BUILD_DIR[$target]:-build}"
        if [ -f "$build_dir/esp32_nat_router.bin" ]; then
            python3 "$SCRIPT_DIR/tools/check_app_size.py" "$build_dir" \
                --name "$target" --limit 100 \
                --baseline "firmware_$target/esp32_nat_router.bin" || true
        fi
    done

    echo ""
    if [ ${#FAILED_TARGETS[@]} -eq 0 ]; then
        print_success "All targets built successfully: ${SELECTED_TARGETS[*]}"
        if [ "$DO_SAVE" = true ]; then
            print_status "firmware_*/ updated. Review with 'git status' before committing."
        else
            print_status "Repository untouched. Pass --save to refresh firmware_*/."
        fi
    else
        print_error "Build failed for ${#FAILED_TARGETS[@]} target(s):"
        for failed_target in "${FAILED_TARGETS[@]}"; do
            print_error "  - $failed_target (${TARGET_DESC[$failed_target]})"
        done
        exit 1
    fi
}

# Handle script interruption
trap 'print_warning "Script interrupted by user"; exit 1' INT

# Run main function
main "$@"
