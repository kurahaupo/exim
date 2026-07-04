# Security Policy

## Supported Versions

We are an open source project with no corporate sponsor and no formal
"support".  In practice, we support the latest released version and work with
OS vendors to make it easy for them to backport fixes for their distributed
packages.  For some security issues, we will issue a patch-release which has
just a simple fix.

We also often have `exim-VERSION+fixes` branches with small things which we
recommend that vendors use.

For postmasters installing Exim manually, we recommend always using the latest
released tarball.

## Reporting a Vulnerability

Our security page is at <https://code.exim.org/exim/exim/wiki/EximSecurity>.
It contains the current contact point and list of PGP keys to use for
encrypting particularly sensitive information.
This also links to our documentation and the chapter on security
considerations.

Before submitting any security report please bear in mind the following

 * We only accept reports against the latest release.
 * Reports should be limited to succinct descriptions of the problem, with minimal code inclusion.
 * Reports where EXPERIMENTAL builds flags are used must be filed as ordinary bugs and are not considered security issues.
 * Reports against isolated source files builds are not accepted. Only reports against the full binary are considered.
 * Do not include Proof of Concepts
 * Do not include suggested patches.
 * Do not include extended diatribes about code flow.
 * Reports we believe are LLM generated will either be rejected outright or if thought to be plausible will be credited to the unnamed and uncredited authors whose works were ingested as the training corpus.
 * Reports that do not meet the criteria for security issues but are merely bugs will be turned into normal public issues.
 * If we do determine there is a security issue then we will release an update on the relevant branch as soon as there is a tested fix. Each issue  will be allocated a GCVE  identifier against our GNA ID, we will no longer be using legacy CVE IDs.

Our security release process is at
<https://code.exim.org/exim/exim/wiki/SecurityReleaseProcess>.
This covers what we do in handling vulnerability reports.

We have no bug bounty program of our own; we're far too disparate a group of
volunteers for such things.
