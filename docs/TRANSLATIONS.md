# Translations

iEasyHash defaults to English and supports Russian (`ru`) and Simplified Chinese (`zh`, HTML `zh-Hans`). A selector on both the sign-in page and the console saves the choice in the `ieasyhash_lang` preference cookie. An absent or unsupported preference falls back to English. Browser language does not override the default.

## Shared catalog

`webapp/static/locales.json` contains language metadata, messages and legacy aliases. Each message uses its English text as the identifier and provides `en`, `ru` and `zh` values. Python templates, application errors and CSV exports use `webapp/i18n.py`; dynamic UI messages use `webapp/static/i18n.js` and the same catalog.

Use `t("English message")` in templates and JavaScript. Escape translated strings when inserting HTML. Retain placeholders such as `{error}` in every translation. Aliases allow older stored Russian worker messages to display in the selected language. Do not translate arbitrary network names, paths, filenames or password values. Raw Hashcat output retains its original technical wording.

## Improving or adding a language

1. Update all affected entries in the shared catalog. Keep message identifiers stable.
2. For a new language, add its native name, formatting locale and HTML language tag under `languages`; add a translation to every message.
3. Extend language selection and formatting in `i18n.js`, and the catalog completeness expectations in `tests/test_i18n.py`. Server-rendered selectors are generated from catalog metadata.
4. Run the API and localization suite, then the synthetic browser checks:

```bash
.venv/bin/python -m pytest -q tests/test_app.py tests/test_i18n.py
.venv/bin/python -m playwright install chromium
.venv/bin/python ops/check_ui.py
```

The browser checks cover English, Russian and Chinese at desktop and mobile widths, preference persistence, navigation, dialogs and sign-in/out. They generate portfolio screenshots from synthetic data in an isolated temporary database. Extend these checks for any new language.
