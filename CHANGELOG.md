# Changelog

## v1.1.0 - 2026-10-11

Follows the vuln.mlab.sh scan API changes, and fixes what they exposed.

### Fixed

- **Several lockfiles no longer fail the job.** Requests were spaced 1 s apart;
  the server now spaces scans by a cooldown (10 s anonymous, 5 s free account),
  so the second lockfile got a 429 that aborted the run. The Action now waits
  out the cooldown the server announces, and on a 429 waits and retries.
- **CVSS vectors are scored.** An advisory carrying only a vector
  (`CVSS:3.1/AV:N/...`) was read as `unknown` severity, so a `fail-on: high`
  gate let it through.
- **One finding per package and CVE.** The same CVE published as several
  advisories (GHSA + RUSTSEC …) was counted once per advisory, inflating `total`.
- Debian and Ubuntu advisories show their CVE (read from `upstream` and from ids
  like `DEBIAN-CVE-…`), so ignore lists by CVE id work on them.
- A file over the size limit (413) is reported with the server's message.

### Added

- Auto-detection of `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`,
  `pdm.lock`, `Pipfile.lock`, `pom.xml`, `gradle.lockfile`, `packages.lock.json`,
  `pubspec.lock`, `mix.lock`, `bom.json` and `bom.xml`.
- Annotations on the lockfile line that declares the package, with the fixed
  version and the advisory summary.
- `fail-on-incomplete` input: fail when some package was not scanned (manifest
  over the package limit, git or path dependency, outage). Reported either way.
- Outputs `critical`, `high`, `medium`, `low`, `unknown`, `incomplete`,
  `not-scanned`.
- Job summary: coverage per lockfile, a "Not fully scanned" section with the
  server's explanation, a "Fixed in" column, the limits of your tier and what the
  next one unlocks.
- Unit tests (`npm test`).

### Changed

- Runs on `node24` (GitHub retires the Node 20 runtime).
- A lockfile that cannot be scanned no longer stops the others: the run scans
  and reports everything, then fails.
- `failed` is also `true` when a lockfile could not be scanned, or when
  `fail-on-incomplete` is set and the scan was incomplete.
