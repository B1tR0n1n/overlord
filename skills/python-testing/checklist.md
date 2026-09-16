# Before you stop

- [ ] Every new code path has a test that fails without it.
- [ ] The suite passes from a clean shell: `pytest -q`.
- [ ] No test depends on ordering, wall-clock time, or files outside the repo.
- [ ] Fixtures are small; shared setup lives in `conftest.py`, not copy-pasted.
