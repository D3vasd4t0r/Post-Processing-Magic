/* Offline UI messages. Only explicit keys/marked labels are rendered; user data is never scanned. */
const I18n = (() => {
  const catalogs = {de: {}, en: {}};
  let locale = 'de';
  try { if (localStorage.getItem('ppm-locale') === 'en') locale = 'en'; } catch { /* storage may be disabled */ }
  const rendered = new WeakMap();
  function t(key, params = {}) {
    const value = catalogs[locale][key] ?? catalogs.de[key] ?? key;
    return value.replace(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g, (match, name) =>
      Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match);
  }
  function apply(root = document) {
    for (const node of root.querySelectorAll('[data-i18n],[data-i18n-aria-label],[data-i18n-placeholder],[data-i18n-title]')) {
      for (const attribute of ['textContent', 'aria-label', 'placeholder', 'title']) {
        const key = node.getAttribute(attribute === 'textContent' ? 'data-i18n' : 'data-i18n-' + attribute);
        if (!key) continue;
        const previous = rendered.get(node) || {};
        const current = attribute === 'textContent' ? node.textContent : node.getAttribute(attribute);
        // An application renderer may have replaced an initial label with a live value/raw output.
        if (attribute === 'textContent' && previous[attribute] !== undefined && current !== previous[attribute]) continue;
        const value = t(key);
        if (attribute === 'textContent') node.textContent = value;
        else node.setAttribute(attribute, value);
        previous[attribute] = value; rendered.set(node, previous);
      }
    }
    document.documentElement.lang = locale;
    const selector = document.getElementById('interface-locale');
    if (selector) selector.value = locale;
  }
  async function setLocale(value) {
    if (!['de', 'en'].includes(value)) throw new Error('Unsupported locale');
    await ready;
    locale = value;
    try { localStorage.setItem('ppm-locale', value); } catch { /* session choice still works */ }
    apply();
    refreshUiText();
  }
  const ready = Promise.all(['de', 'en'].map(async name => {
    const response = await fetch('/locales/web/' + name + '.json');
    if (!response.ok) throw new Error('Cannot load local UI catalog: ' + name);
    catalogs[name] = await response.json();
  })).then(() => apply());
  return {t, apply, setLocale, ready, get locale() { return locale; }, get numberLocale() { return locale === 'en' ? 'en-GB' : 'de-DE'; }};
})();
const t = (key, params) => I18n.t(key, params);
// Explicit app render bindings; no text lookup, DOM observer, HTML rewriting or raw-data translation.
const uiTextBindings = new Map();
function setUiText(node, render, localized = false) {
  node.textContent = render();
  if (localized) uiTextBindings.set(node, render);
  else uiTextBindings.delete(node);
}
function refreshUiText() {
  for (const [node, render] of uiTextBindings) {
    if (node.isConnected) node.textContent = render();
    else uiTextBindings.delete(node);
  }
}
