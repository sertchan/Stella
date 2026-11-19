(() => {
  const sel = [
    '#onetrust-accept-btn-handler', '#didomi-notice-agree-button', '.didomi-continue-without-agreeing ~ button',
    '.qc-cmp2-summary-buttons button[mode="primary"]', '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
    '#CybotCookiebotDialogBodyButtonAccept', '[data-testid="uc-accept-all-button"]', '#uc-btn-accept-banner',
    '.cmpboxbtnyes', '#truste-consent-button', '.fc-cta-consent', '.cc-allow', '.cc-accept', '.cky-btn-accept',
    '#cookie-accept', '#accept-cookies', '#acceptCookies', '.js-accept-cookies', '[aria-label*="Accept" i]',
    '[aria-label*="Kabul" i]', '#cookiescript_accept', '.iubenda-cs-accept-btn', '#axeptio_btn_acceptAll',
    '.osano-cm-accept-all', '#ez-accept-all', '.sp_choice_type_11', 'button[title*="Accept" i]',
    'button[title*="Kabul" i]'];
  const done = [];
  const tryDoc = (doc) => {
    for (const s of sel) { try { const e = doc.querySelector(s); if (e) { e.click(); done.push(s) } } catch (_) {} }
    const words = /^(t[üu]m[üu]n[üu] kabul et|hepsini kabul et|kabul et|kabul ediyorum|t[üu]m [çc]erezleri kabul et|accept all|accept all cookies|accept|allow all|i agree|agree|tamam|onayla|anlad[ıi]m)$/i;
    for (const b of doc.querySelectorAll('button, a[role="button"], a.btn, div[role="button"], span[role="button"], input[type="button"], input[type="submit"]')) {
      const t = (b.innerText || b.value || '').trim();
      if (t.length < 40 && words.test(t)) { try { b.click(); done.push('text:' + t) } catch (_) {} }
    }
  };
  tryDoc(document);
  for (const f of document.querySelectorAll('iframe')) { try { if (f.contentDocument) tryDoc(f.contentDocument) } catch (_) {} }
  if (window.__tcfapi) done.push('tcf');
  return done.join(',');
})()
