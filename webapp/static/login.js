I18n.ready.then(() => {
const {t, locale} = I18n;
const esc = I18n.escape;
const form = document.querySelector('#login-form');
document.querySelector('#toggle-password').addEventListener('click', () => {
  const input = document.querySelector('#password');
  input.type = input.type === 'password' ? 'text' : 'password';
  document.querySelector('#toggle-password').textContent = input.type === 'password' ? t("Show") : t("Hide");
});
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = form.querySelector('button[type=submit]');
  const error = document.querySelector('#login-error');
  error.textContent = '';
  button.disabled = true;
  button.textContent = t("Signing in\u2026");
  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: form.username.value,
        password: form.password.value,
        nonce: document.querySelector('meta[name=login-nonce]').content
      })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(t(result.detail) || t("Sign-in failed"));
    location.replace('/');
  } catch (e) {
    error.textContent = t(e.message);
    button.disabled = false;
    button.innerHTML = `${esc(t("Sign in"))} <span>↗</span>`;
  }
});
}).catch(() => { document.body.dataset.localeError = 'true'; });
