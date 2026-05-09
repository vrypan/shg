#!/usr/bin/env bash
set -euo pipefail

: "${HOMEBREW_TAP_GITHUB_TOKEN:?HOMEBREW_TAP_GITHUB_TOKEN is required}"

owner="vrypan"
repo="shg"
tap_repo="homebrew-tap"
tap_branch="main"
formula_name="shg"
homepage="https://github.com/${owner}/${repo}"
description="Scan shell history files for accidentally persisted secrets."
license_name="MIT"
commit_name="Panagiotis Vryonis"
commit_email="58812+vrypan@users.noreply.github.com"

tag="${1:-${GITHUB_REF_NAME:-}}"
if [[ -z "${tag}" ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi
version="${tag#v}"

source_url="https://github.com/${owner}/${repo}/archive/refs/tags/${tag}.tar.gz"
source_sha256="$(curl -fsSL "${source_url}" | shasum -a 256 | awk '{print $1}')"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

git clone \
  "https://x-access-token:${HOMEBREW_TAP_GITHUB_TOKEN}@github.com/${owner}/${tap_repo}.git" \
  "${tmpdir}/tap"

formula_dir="${tmpdir}/tap/Formula"
mkdir -p "${formula_dir}"
formula_path="${formula_dir}/${formula_name}.rb"

cat >"${formula_path}" <<EOF
class Shg < Formula
  desc "${description}"
  homepage "${homepage}"
  url "${source_url}"
  sha256 "${source_sha256}"
  version "${version}"
  license "${license_name}"

  depends_on "zig" => :build

  def install
    system "zig", "build", "--prefix", prefix
    (share/"shg/extras").install Dir["extras/*"]
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/shg version")
  end
end
EOF

git -C "${tmpdir}/tap" config user.name "${commit_name}"
git -C "${tmpdir}/tap" config user.email "${commit_email}"
git -C "${tmpdir}/tap" add "Formula/${formula_name}.rb"

if git -C "${tmpdir}/tap" diff --cached --quiet; then
  echo "Homebrew formula already up to date."
  exit 0
fi

git -C "${tmpdir}/tap" commit -m "Brew formula update for ${formula_name} version ${tag}"
git -C "${tmpdir}/tap" push origin "${tap_branch}"
