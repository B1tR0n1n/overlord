---
name: python-testing
description: How to add and run tests in a Python project with pytest, and what a good test looks like here.
when: the task touches Python code and mentions tests, coverage, a bug fix, or "make sure it works".
---

# Python testing

1. Find how tests already run: `pytest -q` from the project root; a `pyproject.toml`
   or `setup.cfg` may pin options. Run the existing suite once before changing anything.
2. One behaviour per test, named for the behaviour: `test_rejects_empty_name`, not `test_1`.
3. Reproduce a bug with a failing test first; the fix makes it pass. Keep the test.
4. Prefer plain `assert` with a message over custom helpers. No sleeps; no network.
5. Finish with the whole suite green and say which command you ran.

See `checklist.md` for the review checklist to apply before you stop.
