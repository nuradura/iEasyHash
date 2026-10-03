# iEasyHash contributor instructions

Read README.md and docs/INSTALL.md before changing the application.

- Application code lives in webapp/. Keep authentication, CSRF, noindex, local assets and protected exports.
- Support WPA mode 22000 with dictionary passes only. The application does not capture wireless traffic.
- Never commit captures, recovered passwords, potfiles, databases, wordlists, cookies, deployment credentials or FIRST_LOGIN.md.
- Run API tests against temporary data. GPU tests use synthetic PMKIDs and require explicit opt-in.
- Queue inputs are snapshots. Keep one worker and the process lock; do not mutate an active queue.
- Preserve browser accessibility, mobile layouts and the iEasyHash paper/graphite/teal/orange palette.
- Keep deployment listening on loopback. TLS and remote access are configured by each operator.
