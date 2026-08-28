# ObjectShare Project Memory

This file records mistakes made during the 2026 modernization work so future work
does not repeat them. It is a repository-local memory and should remain alongside
`AGENTS.md`.

## Recorded mistakes

1. The README TODO and supported-storage checklists were removed instead of being
   preserved and updated. The roadmap is user-owned project history; completing
   work does not justify deleting it.
2. The Tabler HTML theme was removed during modernization even though it is part of
   the project's intended look and feel.
3. The footer attribution containing the heart icon and "Made with ... by Cat" was
   removed without authorization.
4. HTMX was treated as unnecessary even though the user intends to use it for
   future login and user-management functionality.
5. Configuration migration initially failed to preserve the user's existing
   `config.json` values as an explicit requirement.
6. PostgreSQL timezone handling produced `Asia%2FTaipei` instead of `Asia/Taipei`,
   causing database initialization to fail. URL encoding was applied at the wrong
   semantic layer.
7. CORS was mentioned without making its configuration location sufficiently
   explicit and consistent across the configuration examples and documentation.
8. `workflow_runs_clean_up.yml` and `release.yml` were deleted instead of being
   retained and secured in place. This discarded intentional automation and
   release behavior.
9. The chosen `Mattraks/delete-workflow-runs` action was replaced with a custom API
   script without the user's approval. The correct response was to retain the
   chosen action, pin it to an exact commit, and scope its permissions.
10. Optional Docker Hub publication was implemented as
    `name=,enable=false` for `docker/metadata-action`. The action validates the
    empty image name before honoring the disabled flag, so the GHCR-only release
    path failed in CI.
11. The GHCR image was initially derived directly from the mixed-case GitHub
    repository name. Docker repository paths must be normalized to lowercase.
12. The container workflow was linted but the most important optional-config
    branch was not behaviorally validated before handoff. Future validation must
    cover both GHCR-only and GHCR-plus-Docker-Hub cases.
13. The release asset job ran `gh release upload` without either checking out the
    repository or passing `--repo`. GitHub CLI tried to infer the repository from
    `.git` and failed. Non-checkout jobs must always provide repository context
    explicitly to `gh` commands.

## Standing decisions

- Keep the README roadmap visible and truthful.
- Keep Tabler, HTMX, and the author's footer credit.
- Keep both legacy workflow filenames and their intended behavior.
- Use `Mattraks/delete-workflow-runs` for run cleanup.
- Publish containers to GHCR unconditionally and to Docker Hub only when fully
  configured.
- Preserve real configuration values during schema migrations without exposing
  secrets.

When a future request conflicts with one of these decisions, follow the user's new
explicit instruction and update this memory so it remains accurate.
