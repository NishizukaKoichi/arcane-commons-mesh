# Release and installation

Arcane Commons Mesh publishes the `acmctl` command-line application as immutable
GitHub Release assets. The release pipeline builds from an exact `vX.Y.Z` tag on
GitHub-hosted macOS, Linux, and Windows runners and publishes a SHA-256 file next
to every archive.

## Install a release

1. Open the repository's [Releases](https://github.com/NishizukaKoichi/arcane-commons-mesh/releases)
   page and download the archive for the current operating system.
2. Download the adjacent `.sha256` file and verify it before extracting:

   ```sh
   shasum -a 256 -c acmctl-macos-apple-silicon.tar.gz.sha256
   ```

   Linux users may use `sha256sum -c` instead. On Windows, compare
   `Get-FileHash .\acmctl-windows-x86_64.zip -Algorithm SHA256` with the value in
   the downloaded checksum file.
3. Extract the archive, then run `./acmctl doctor` (or `.\acmctl.exe doctor` on
   Windows). A Git checkout is optional for this check.

The release archive contains the executable, license, and README. The executable
is not code-signed or notarized. Operating systems may therefore show an
unidentified-developer warning. Do not bypass an operating-system warning unless
the downloaded checksum matches the release checksum and the repository URL is
the expected one.

## Maintainer release procedure

Use only a clean `main` branch whose local gates and GitHub CI are green.

```sh
git tag -s vX.Y.Z -m "Arcane Commons Mesh vX.Y.Z"
git push origin vX.Y.Z
```

A signed tag is preferred. An annotated tag is acceptable only when the local
Git signing setup is unavailable and that exception is recorded. The tag push
triggers `.github/workflows/release.yml`; no binary is built on a maintainer's
workstation or uploaded by hand.

After publication, verify all four platform archives and checksum files are
present, inspect the workflow result, download one archive on a clean machine,
verify its checksum, run `acmctl doctor`, and run `acmctl verify-commons` from a
writable directory. A release is not a security audit and must retain the
warning that v1 is not the only safe copy of valuable data and does not prove a
production TEE or payment settlement.

## Rollback

Git tags and published artifacts are immutable evidence. If a release is wrong,
do not replace its files. Mark the release as withdrawn, document the reason,
fix forward, and publish a new patch version.
