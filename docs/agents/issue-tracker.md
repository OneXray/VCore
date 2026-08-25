# Issue tracker: GitHub

Issues and specs live in this repository's GitHub Issues.

Repository: `OneXray/VCore`

Pass `--repo OneXray/VCore` explicitly because development often runs from a workspace containing multiple repositories.

## Operations

- Create: `gh issue create --repo OneXray/VCore --title "..." --body "..."`
- Read: `gh issue view <number> --repo OneXray/VCore --comments`
- List: `gh issue list --repo OneXray/VCore --state open --json number,title,body,labels,comments`
- Comment: `gh issue comment <number> --repo OneXray/VCore --body "..."`
- Label: `gh issue edit <number> --repo OneXray/VCore --add-label "..."`
- Close: `gh issue close <number> --repo OneXray/VCore --comment "..."`

## Pull requests as a triage surface

PRs as a request surface: no.

## Skill conventions

When a skill says "publish to the issue tracker", create a GitHub issue. When it says "fetch the relevant ticket", read the referenced GitHub issue, including comments and labels.

## Wayfinding

- Map: one issue labelled `wayfinder:map`.
- Child: a sub-issue labelled `wayfinder:<type>`.
- Blocking: use native GitHub issue dependencies; fall back to a `Blocked by: #<n>` line when unavailable.
- Frontier: first open, unblocked, unassigned child in map order.
- Claim: assign the issue to the driving developer before work.
- Resolve: comment with the answer, close the issue, then update the map's Decisions-so-far.
