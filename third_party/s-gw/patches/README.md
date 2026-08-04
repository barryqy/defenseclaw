# DefenseClaw patch queue

If DefenseClaw needs an s-gw change before its standalone release, store a
numbered `git format-patch` file here and list it in `series`. The module build
must apply the queue in that order and fail if any patch no longer applies.
Every patch must also have a matching standalone s-gw pull request or commit.

Current queue:

1. `0001-defenseclaw-native-runtime-boundary.patch` advances the package to
   0.2.0, adds the packaged Linux Secret Service helper contract, and hardens
   Windows helper command admission. It disables the bundled Node console,
   service, and app surfaces and intentionally contains no TypeScript proxy
   tokenizer, quarantine, restricted MCP fallback, or enrollment approval
   mutation. The DefenseClaw
   native gateway admits and launches the signed runner for raw proxy
   tokenization and user-presence approval. The patch must be applied to
   standalone s-gw before the integrated DefenseClaw release is pushed.
2. `0002-defenseclaw-native-authorization-hardening.patch` rejects every CLI
   `--allow-command` enrollment path before store construction and removes
   native app, service, menu bar, and browser work from restricted setup.
   Command authorization and approval UI remain owned by the admitted native
   runner.
3. `0003-update-fast-uri.patch` refreshes the transitive `fast-uri` lock entry
   from 3.1.2 to 3.1.5 to remove the reviewed high-severity production
   advisories without changing the exact upstream source mirror.
4. `0004-update-mcp-sdk-dependencies.patch` refreshes the MCP SDK and its Hono
   and IP-address runtime dependencies, together with the PostCSS build chain,
   to remove their reviewed advisories without changing the exact upstream
   source mirror.
5. `0005-platform-credential-source-metadata.patch` lets the credential-store
   provider choose default source metadata instead of hard-coding the macOS
   keychain. Its Linux runtime regression covers setup and keychain enrollment
   through a fake Secret Service helper. This matches standalone s-gw commit
   `ec1912085f0747d725dac32ca3d26e19c412abf2`.
6. `0006-windows-safe-tsx-launcher.patch` starts TypeScript test entrypoints
   through Node and the portable `tsx` module CLI instead of invoking a
   platform-specific package-manager shim. This matches standalone s-gw commit
   `e05cc5b5760fea969cfed88d7a2e0cef4dd3500d`.
7. `0007-defenseclaw-setup-help.patch` makes `s-gw setup --help` and
   `s-gw setup -h` print the restricted DefenseClaw setup contract before any
   credential-store, service, or UI work. This adapts standalone s-gw commit
   `af4f01cf0e8bd061778da83c6d2a6e7034ae7b16` to the integrated runtime.
