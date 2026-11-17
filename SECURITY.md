# Security policy

## Supported versions

pwv is pre-release: no version is supported yet. From v1.0.0 on, the latest
release is supported; fixes are not backported to older releases.

## Reporting a vulnerability

Report suspected vulnerabilities **privately**, through GitHub's private
vulnerability reporting ("Security" tab of this repository, "Report a
vulnerability"), not in a public issue or pull request. Please include the
version or commit, what you observed, and how to reproduce it.

Never include real vault files, passwords, or other secrets in a report. If
a reproduction needs a vault, create one with a throwaway password.

## Verifying a release

Each release file is built by `.github/workflows/release-build.yml` from a
version tag, after two independent builds were checked to be bit-identical
(T-REPRO-1). The binary, its two licence files, and `SHA256SUMS` carry a
GitHub artifact attestation (Sigstore). Verify a download with the GitHub CLI
before you run it:

    gh attestation verify pwv-<version>-x86_64-linux \
      --repo TheDansmod/password_manager \
      --signer-workflow TheDansmod/password_manager/.github/workflows/release-build.yml
    sha256sum -c SHA256SUMS

The first command proves that the file was built by that workflow from this
repository; the second, that it matches the attested checksum list.
