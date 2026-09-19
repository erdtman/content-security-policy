# Releasing

Releases are published to npm by `.github/workflows/publish.yml`, which runs
on a `v*` tag push. Every published version carries a
[provenance attestation](https://docs.npmjs.com/generating-provenance-statements)
linking the tarball back to the commit and workflow run that produced it.

No npm token is stored in this repository. Publishing authenticates with a
short-lived OIDC token issued to the workflow run, via npm's trusted
publishing.

## One-time setup

This has to be done once, by a maintainer of the npm package, and cannot be
done from this repository.

1. Sign in to npmjs.com as a maintainer of `content-security-policy`.
2. Go to the package page → **Settings** → **Trusted publishers**.
3. Add a GitHub Actions publisher:

   | Field | Value |
   | --- | --- |
   | Organization or user | `erdtman` |
   | Repository | `content-security-policy` |
   | Workflow filename | `publish.yml` |
   | Environment | leave blank |

Leave the environment blank, matching the canonicalize setup. If you ever fill
it in, the workflow needs a matching `environment:` block, because npm checks
that claim against the OIDC token. A human gate is not a reason to add one
here: staging already provides it.

Do not set `NODE_AUTH_TOKEN` or any other npm credential in the job. A token in
the environment suppresses the OIDC exchange, and the publish then fails with
ENEEDAUTH.

## Why the registry is pinned in the manifest

`publishConfig.registry` names registry.npmjs.org explicitly. Without it,
`npm publish` follows whatever registry the machine or runner is configured
for, and a developer whose npm points at a company mirror would publish this
public package there instead. Pinning it in the manifest makes the target a
property of the package rather than of the environment.

## Cutting a release

```sh
# 1. Make sure master is green and the changelog is up to date.
git switch master && git pull

# 2. Move the Unreleased section of CHANGELOG.md under the new version
#    heading, then commit that edit.

# 3. Bump the version and create the tag. Use minor/major as appropriate.
npm version minor

# 4. Push the commit and the tag. The tag push starts the workflow.
git push --follow-tags
```

The workflow stages the release rather than publishing it: it uploads the
tarball and signs provenance, but the version does not appear on the registry
until it is promoted. Promote it with `npm stage approve <stage-id>` or from
the package page on npmjs.com. So a tag push alone cannot ship a version.

The workflow refuses to stage anything if the tag does not match the version in
`package.json`, so a mistyped tag fails loudly instead of shipping the wrong
version.

## Verifying a published release

```sh
npm view content-security-policy versions
npm audit signatures
```

The npm package page shows a **Provenance** section with the source commit and
the workflow run that built it.
