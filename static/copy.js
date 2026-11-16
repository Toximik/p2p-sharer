// Copy buttons: <button data-copy="#input-id"> or a button right after an <input>.
document.addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-copy], .copybtn");
  if (!btn) return;
  const input = btn.dataset.copy ? document.querySelector(btn.dataset.copy) : btn.previousElementSibling;
  if (!input) return;
  input.select();
  const label = btn.textContent;
  const done = () => { btn.textContent = "Copied"; setTimeout(() => (btn.textContent = label), 1500); };
  const legacy = () => { try { if (document.execCommand("copy")) done(); } catch (_) {} };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(input.value).then(done, legacy);
  else legacy();
});
