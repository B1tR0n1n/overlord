---
name: conventional-commits
description: Write commit messages and change summaries in the Conventional Commits form so tooling can read them.
when: you are asked to commit, to summarise a change for a changelog, or the project's history already uses "feat:", "fix:" prefixes.
---

# Conventional commits

`<type>(<scope>): <summary>` — type is one of feat, fix, docs, refactor, test,
chore, perf, build, ci; scope is the module touched; summary is imperative,
lower-case, no trailing period, under 72 characters.

A body explains *why*, not what (the diff says what). A breaking change gets a
`BREAKING CHANGE:` footer. One logical change per commit.
