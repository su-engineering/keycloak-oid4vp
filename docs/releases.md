# GitHub releases

Versioned provider JARs and checksums are available under [Releases](https://github.com/su-engineering/keycloak-oid4vp/releases). Repository access is required while the repository is private.

Each release contains a separate JAR for Keycloak **26.5.4** and **26.5.5**, plus `SHA256SUMS`. Use Java 21 and the JAR matching your runtime. Prereleases are for integration testing and are explicitly marked on GitHub.

## Download and install

For example, using the authenticated GitHub CLI:

```sh
gh release download v0.1.0-rc.1 --repo su-engineering/keycloak-oid4vp \
  --pattern '*.jar' --pattern SHA256SUMS --dir release
cd release
sha256sum --check SHA256SUMS
cp keycloak-extension-oid4vp-0.1.0-rc.1-keycloak-26.5.5.jar keycloak-extension-oid4vp.jar
```

Follow [installation](installation.md#add-it-to-keycloak) and [migration](migration.md). Keep the original versioned filename and checksum in your deployment record, and install only one provider JAR.

## Create the next release

1. Choose `X.Y.Z` for a stable release or `X.Y.Z-rc.N` (also `alpha.N` and `beta.N`) for a prerelease.
2. Set the root `pom.xml` version to that exact value and add `docs/releases/<version>.md` with features, upgrade notes, validation and limitations. Update the changelog.
3. Commit and push the prepared changes to `main`. Check CI and complete deployment-specific issuer/wallet acceptance testing before promoting a stable release.
4. Create and push an annotated tag for that commit:

   ```sh
   git tag -a v0.1.0-rc.1 -m 'Keycloak OID4VP 0.1.0-rc.1'
   git push origin v0.1.0-rc.1
   ```

   Substitute the new version for both commands.

The [Release workflow](../.github/workflows/release.yaml) validates the tag, matching Maven version, release notes and membership in `main` history. It then runs the existing full CI matrix, retains each tested JAR, and publishes those exact artifacts with checksums. A failed test prevents publication. Publication uses the built-in `GITHUB_TOKEN`; no publishing secret is required. Only the publishing job receives repository write permission.

Tags with `-alpha.N`, `-beta.N` or `-rc.N` create prereleases. Stable tags use GitHub's normal latest-release selection. Releases do not publish to Maven Central or a container registry.

If a run fails before publication, use **Actions → Release → Re-run failed jobs**, or manually run the workflow with the existing tag selected. Do not move a tag or replace an already published binary: prepare another version for code changes. A published release makes a repeated create step fail rather than overwrite its assets.
