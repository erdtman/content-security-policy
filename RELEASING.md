# Releasing

Releases are published to npm by `.github/workflows/release.yml`, which runs
when a GitHub Release is published. Every published version carries a
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
   | Workflow filename | `release.yml` |
   | Environment | `npm` |

The environment name must match the `environment:` block in the release
workflow. Leave it blank there if you do not want to use one, but an
environment lets you add required reviewers, so a publish needs a second pair
of eyes.

If you would rather use a token than trusted publishing, create a granular
access token scoped to this package, store it as the `NPM_TOKEN` repository
secret, and add to the publish step:

```yaml
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Provenance still works that way; trusted publishing is preferred only because
there is no long-lived credential to leak or rotate.

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

# 4. Push the commit and the tag.
git push --follow-tags
```

Then create a GitHub Release for the new tag, using the changelog section as
the body. Publishing the release starts the workflow.

The workflow will refuse to publish if the release tag does not match the
version in `package.json`, so a mistyped tag fails loudly instead of shipping
the wrong version.

## Verifying a published release

```sh
npm view content-security-policy versions
npm audit signatures
```

The npm package page shows a **Provenance** section with the source commit and
the workflow run that built it.
