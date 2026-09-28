# Issue tracker: GitHub

Issues and specs live in GitHub Issues for `OneXray/VCore`.

Use `gh`. Every issue or PR command must specify `--repo OneXray/VCore`.
For `gh api`, use an explicit `repos/OneXray/VCore/...` endpoint. Before publishing,
verify that `origin` and the resolved GitHub repository still identify this project.

## Operations

- Publish a request/spec: `gh issue create --repo OneXray/VCore --title "..." --body-file <file>`.
- Read a ticket: `gh issue view <number> --repo OneXray/VCore --comments`.
- List tickets: `gh issue list --repo OneXray/VCore --state open --json number,title,body,labels,comments`.
- Comment: `gh issue comment <number> --repo OneXray/VCore --body-file <file>`.
- Apply/remove labels: `gh issue edit <number> --repo OneXray/VCore --add-label "..."` / `--remove-label "..."`.
- Close: `gh issue close <number> --repo OneXray/VCore --comment "..."`.

Read a referenced ticket's body, comments, and labels before acting on it.
Use the [label mappings](triage-labels.md) for canonical triage roles.
Issue and PR numbers share a namespace; resolve the object type before acting.

## Pull requests as a triage surface

**PRs as a request surface: no.**

Issues hold requests and specs; PRs hold implementation changes.

## Wayfinding operations

- Keep one map issue labelled `wayfinder:map`, containing Notes,
  Decisions-so-far, and Fog.
- Link child tickets through GitHub sub-issues. If unavailable, use a task
  list in the map and `Part of #<map>` in each child.
- Label children `wayfinder:<type>`: research, prototype, grilling, or task.
- Use native issue dependencies for blockers. If unavailable, record
  `Blocked by: #<number>` in the child and inspect those issues' states.
- A child is unblocked only when every blocker is closed.
- Select the first open, unassigned, unblocked child in map order.
- Claim it with `gh issue edit <number> --repo OneXray/VCore --add-assignee @me`.
- Resolve by commenting the result, closing the ticket, and appending
  a concise result and evidence link to the map's Decisions-so-far.
