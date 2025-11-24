#!/usr/bin/env bash

# Run via `make check-spelling`

# kindly provided by https://github.com/rancher-sandbox/rancher-desktop/blob/0a941a3f8ad4a0d37a65ec3d75ee701055826c7e/scripts/spelling.sh
# Our changes:
# * optional overwrite of the check-spelling repo path
# * mandatory check-spelling version
# * INPUTS to match spelling action config
# * dealing with git user overwrite (until fixed in upstream)

set -o errexit -o nounset

check_prerequisites() {
    if [[ -n ${CI:-} && -z ${RD_LINT_SPELLING:-} ]]; then
        echo "Skipping spell checking in CI."
        exit
    fi

    case $(uname -s) in # BSD uname doesn't support long option `--kernel-name`
        Darwin) check_prerequisites_darwin;;
        Linux) check_prerequisites_linux;;
        CYGWIN*|MINGW*|MSYS*) check_prerequisites_windows;;
        *) printf "Prerequisites not checked on %s\n" "$(uname -s)" >&2 ;;
    esac
}

check_prerequisites_darwin() {
    if command -v cpanm &>/dev/null; then
        return
    fi
    echo "Please install cpanminus first:" >&2
    if command -v brew &>/dev/null; then
        echo "brew install cpanminus" >&2
    fi
    exit 1
}

check_prerequisites_linux() {
    if command -v wslpath >&/dev/null; then
        check_prerequisites_windows
        return
    fi
    if [[ -z "${PERL5LIB:-}" ]]; then
        export PERL5LIB=$HOME/perl5/lib/perl5
    fi
    if command -v cpanm &>/dev/null; then
        return
    fi
    echo "Please install cpanminus first:" >&2
    if command -v zypper &>/dev/null; then
        echo "zypper install perl-App-cpanminus" >&2
    elif command -v apt &>/dev/null; then
        echo "apt install cpanminus" >&2
    fi
    exit 1
}

check_prerequisites_windows() {
    # cygwin, mingw, msys, or WSL2.
    echo "Skipping spell checking, Windows is not supported."
    exit
}

# Locate the spell checking script, cloning the GitHub repository if necessary.
find_script() {
    # Put the check-spelling files in `$PWD/resources/host/check-spelling`
    local checkout=${LOCAL_CHECK_SPELLING:-$PWD/resources/host/check-spelling}
    local script=$checkout/unknown-words.sh
    local repo=https://github.com/check-spelling/check-spelling
    local version=${CHECK_SPELLING_VERSION}

    if [[ ! -d "$checkout" ]]; then
        git clone --branch "$version" --depth 1 "$repo" "$checkout" >&2
    else
        git -C "$checkout" fetch origin "$version" >&2
        git -C "$checkout" checkout "$version" >&2
    fi

    if [[ ! -x "$script" ]]; then
        printf "Failed to checkout check-spelling@%s: %s not found.\n" "$version" "$script" >&2
        exit 1
    fi

    echo "$script"
}

check_prerequisites
script=$(find_script)

INPUTS=$(yq --output-format=json <<EOF
    suppress_push_for_open_pull_request: 1
    checkout: true
    check_file_names: 1
    post_comment: 0
    use_sarif: 1
    check_extra_dictionaries: ""
    dictionary_source_prefixes: >
        {
            "cspell": "https://raw.githubusercontent.com/check-spelling/cspell-dicts/v20241114/dictionaries/",
            "census": "https://raw.githubusercontent.com/check-spelling-sandbox/census/dictionaries-d90e686f89dd241ad61d30f26619e54d73e73c6e/dictionaries/"
        }
    extra_dictionaries:
        census:census-5.txt
        cspell:software-terms/softwareTerms.txt
        cspell:golang/go.txt
        cspell:php/php.txt
        cspell:k8s/k8s.txt
        cspell:node/node.txt
        cspell:lua/lua.txt
        cspell:filetypes/filetypes.txt
        cspell:html/html.txt
        cspell:python/common/extra.txt
        cspell:python/python/python-lib.txt
        cspell:dart/dart.txt
        cspell:aws/aws.txt
        cspell:django/django.txt
        cspell:fullstack/fullstack.txt
EOF
)

export INPUTS

if [[ -z "${GITHUB_STEP_SUMMARY:-}" ]]; then
    # check-spelling falls over without this set; it writes to this file.
    export GITHUB_STEP_SUMMARY=/dev/null
fi

# dealing with git author change in check-spelling v0.0.25
cp -p .git/config .gitconfig_bk
trap 'mv .gitconfig_bk .git/config' EXIT

#exec "$script"
$script
