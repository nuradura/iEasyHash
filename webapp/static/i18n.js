'use strict';
window.I18n = (() => {
  const htmlLang = document.documentElement.lang;
  const language = htmlLang.startsWith('zh') ? 'zh' : htmlLang === 'ru' ? 'ru' : 'en';
  const locale = {en: 'en-US', ru: 'ru-RU', zh: 'zh-CN'}[language];
  let catalog;
  const escape = value => String(value ?? '').replace(/[&<>"']/g,
    char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  function t(message) {
    if (message == null) return '';
    const key = Object.hasOwn(catalog.aliases, message) ? catalog.aliases[message] : message;
    const entry = Object.hasOwn(catalog.messages, key) ? catalog.messages[key] : null;
    if (entry) return entry[language] || entry.en;
    const oldWorker = String(message).match(/^Ошибка worker: ([A-Za-z0-9_]+)\. Проверьте доступность файлов и журнал службы\.$/);
    if (oldWorker) return t('Worker error: {error}. Check file availability and service logs.').replace('{error}', oldWorker[1]);
    return message;
  }
  const selector = document.querySelector('#language-select');
  selector?.addEventListener('change', () => {
    if (!['en', 'ru', 'zh'].includes(selector.value)) return;
    document.cookie = 'ieasyhash_lang=' + selector.value + '; Path=/; Max-Age=31536000; SameSite=Strict'
      + (location.protocol === 'https:' ? '; Secure' : '');
    location.reload();
  });
  const ready = fetch('/static/locales.json').then(response => {
    if (!response.ok) throw new Error('Language catalog unavailable');
    return response.json();
  }).then(value => { catalog = value; });
  return {language, locale, escape, t, ready};
})();
