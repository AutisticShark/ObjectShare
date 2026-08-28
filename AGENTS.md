# ObjectShare Agent Instructions

These instructions apply to every change in this repository.

## Preserve the project

- Treat existing features, workflows, UI libraries, documentation, roadmap items,
  credits, and configuration values as intentional unless the user explicitly
  authorizes their removal.
- Modernization is not permission to redesign the product or delete historical
  functionality. Prefer focused, compatible changes.
- Before removing a file, dependency, workflow, asset, HTML fragment, or README
  section, inspect its current use and Git history. If it might be intentional,
  preserve it and secure or update it in place.
- Never remove or rewrite the README roadmap merely because work was requested on
  its TODOs. Keep the checklist and update each item's status accurately.
- Preserve the Tabler-based UI and the footer credit, including the heart icon and
  "Made with ... by Cat", unless the user explicitly requests a visual redesign or
  attribution change.
- Preserve HTMX. It is part of the planned implementation for login, user
  management, authentication, and authorization features.

## Preserve automation behavior

- Do not delete or silently replace established GitHub Actions workflows. In
  particular, preserve `release.yml`, `workflow_runs_clean_up.yml`, and their
  established triggers and behavior.
- Secure workflows in place with least-privilege permissions and full commit-SHA
  action pins. Do not mistake a third-party action for unwanted code when the user
  deliberately chose it.
- `workflow_runs_clean_up.yml` must use `Mattraks/delete-workflow-runs`, retain runs
  for seven days, and keep at least one run per workflow unless the user requests a
  policy change.
- Container publication must always support GHCR. Docker Hub must remain optional:
  when any Docker Hub setting is missing, do not log in and do not pass an empty
  Docker Hub image to downstream actions.
- Construct optional `docker/metadata-action` image entries conditionally. An entry
  such as `name=,enable=false` is invalid because the empty name is still parsed.
- Normalize the GHCR repository path to lowercase before using it as a Docker image
  name.
- Validate workflow edits with `actionlint` and test important configuration
  branches, especially the zero-secret/default path, not only the fully configured
  path.

## Configuration compatibility

- Migrate `config.json` without losing or overwriting existing user values. Treat
  the real file as potentially secret; never print its credentials or copy them
  into examples, logs, or commits.
- Every new configuration option must be implemented consistently in the parser,
  validation, `config.json.example`, `.env.example` when applicable, and README.
  Documentation must state exactly where the option belongs.
- Do not percent-encode PostgreSQL timezone names as plain parameter values. Values
  such as `Asia/Taipei` must reach PostgreSQL unchanged rather than as
  `Asia%2FTaipei`. Add coverage for values containing `/` when changing DSN logic.

## Product constraints

- When deployed behind Cloudflare, large uploads must use the supported direct-to-
  object-storage flow so request bodies do not traverse the proxied application
  endpoint. Do not describe evasion of provider limits as a production design.
- Preserve security boundaries when adding direct uploads: short-lived scoped
  presigned URLs, server-side authorization, size/type constraints, and a finalize
  step are required.

## Required change discipline

- Review `git diff` and `git status` before and after edits. Keep unrelated user
  changes intact.
- For dependency or security upgrades, research current primary documentation,
  preserve behavior, and explain any unavoidable breaking change before making it.
- A syntax check alone is insufficient for configuration-heavy changes. Exercise
  the relevant behavior matrix and report what was actually verified.
- See `MEMORY.md` for the concrete failures that established these rules.
