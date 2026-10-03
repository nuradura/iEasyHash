# Contributing

Use Python 3.13 and install requirements-dev.txt in a virtual environment. Run the API suite before submitting a change:

```bash
.venv/bin/python -m pytest -q tests/test_app.py
```

Run synthetic GPU tests when changing process lifecycle or checkpoints and describe your GPU, driver and Hashcat versions in the pull request. Do not use personal network captures in tests or screenshots.

Keep changes focused. Explain the problem, resulting behavior and validation. Preserve authentication, CSRF, protected exports, immutable queues and single-worker execution.

Report security problems privately through GitHub's private vulnerability reporting when available. Do not include passwords, cookies, potfiles or runtime databases in an issue.
