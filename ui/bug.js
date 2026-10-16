// ============================================================ «Нашёл ошибку?»
// Человек пишет, что случилось, видит весь отчёт до отправки, отчёт уходит автору в Telegram (через посредник Cloudflare Worker).
// Плюс журнал ошибок окна: необработанные ошибки JavaScript уходят в data\errors.log, чтобы их можно было приложить к отчёту.

const BUG = {open: false, sending: false};

function bugPage(){
  try { const p = PAGES.find(x => x.id === PAGE); const t = (tabsOf(p) || []).find(x => x[0] === SUB); return [p?.t, t?.[1]].filter(Boolean).join(" → ") }
  catch { return "" }
}

async function bugReport(prefill = {}){
  if (BUG.open) return;
  BUG.open = true;
  const ctx = {page: prefill.page || bugPage(), error: prefill.error || ""};
  const wrap = document.createElement("div");
  wrap.className = "mdl-back";
  wrap.innerHTML = `<div class="mdl xwide bug-dlg" role="dialog" aria-modal="true" aria-labelledby="bugT">
    <div class="mdl-top"><span class="mdl-ic">!</span><h3 id="bugT">Нашёл ошибку в ScanHub?</h3></div>
    <p>Напиши, что пошло не так — отчёт уйдёт автору ScanHub. Ты увидишь его целиком до отправки.</p>
    ${ctx.error ? `<div class="note bad">Ошибка на экране: ${esc(ctx.error)}</div>` : ""}
    <label class="bug-f"><span class="bug-h">Что случилось <span class="sub">— обязательно</span></span>
      <textarea id="bugText" rows="4" placeholder="Например: нажал «Очистить», крутится уже 10 минут и ничего не происходит"></textarea></label>
    <label class="bug-f"><span class="bug-h">Что делал перед этим <span class="sub">— по желанию, очень помогает</span></span>
      <textarea id="bugSteps" rows="3" placeholder="1. Открыл «Очистка» 2. Отметил «Временные файлы» 3. Нажал «Очистить»"></textarea></label>
    <label class="bug-f"><span class="bug-h">Как с тобой связаться, если будут вопросы <span class="sub">— по желанию</span></span>
      <input id="bugContact" type="text" maxlength="120" placeholder="Telegram @ник или почта"></label>
    <label class="bug-chk"><input type="checkbox" id="bugTech" checked> Приложить технические сведения: версия ScanHub и Windows, раздел, последние ошибки из журнала ScanHub</label>
    <details class="bug-prev" id="bugPrevBox"><summary>Что уйдёт автору</summary><pre id="bugPrev" class="mono">…</pre>
      <div class="sub">Имя пользователя, имя компьютера, почта и ключи убраны. Больше ничего не отправляется: ни файлы, ни история проверок.</div></details>
    <div class="note warn" id="bugNote" hidden></div>
    <div class="mdl-btns"><button data-bug-x>Отмена</button><button class="ghost" data-bug-copy hidden>Скопировать отчёт</button><button class="primary" data-bug-send>Отправить</button></div>
  </div>`;
  document.body.appendChild(wrap);
  const $w = s => wrap.querySelector(s);
  const fields = () => ({text: $w("#bugText").value, steps: $w("#bugSteps").value, contact: $w("#bugContact").value,
                         tech: $w("#bugTech").checked, page: ctx.page, error: ctx.error});
  const note = (t, kind = "warn") => { const n = $w("#bugNote"); n.hidden = !t; n.className = "note " + kind; n.textContent = t || "" };
  let ready = true;
  const preview = async () => {
    try { const r = await api("/api/report/preview", fields()); $w("#bugPrev").textContent = r.text; ready = r.ready;
      if (!ready) { note("Отправка отчётов в этой копии ScanHub не настроена. Скопируй отчёт и отправь автору сам."); $w("[data-bug-send]").hidden = true; $w("[data-bug-copy]").hidden = false } }
    catch (e) { $w("#bugPrev").textContent = "Не получилось собрать отчёт: " + e.message }
  };
  const close = () => { wrap.classList.add("out"); setTimeout(() => wrap.remove(), 140); BUG.open = false; document.removeEventListener("keydown", key, true) };
  const key = e => { if (e.key === "Escape" && !BUG.sending) { e.preventDefault(); e.stopPropagation(); close() } };
  document.addEventListener("keydown", key, true);
  $w("#bugPrevBox").addEventListener("toggle", e => { if (e.target.open) preview() });
  $w("#bugTech").addEventListener("change", () => { if ($w("#bugPrevBox").open) preview() });
  wrap.addEventListener("click", async e => {
    if (e.target === wrap || e.target.closest("[data-bug-x]")) { if (!BUG.sending) close(); return }
    if (e.target.closest("[data-bug-copy]")) {
      await preview();
      try { await navigator.clipboard.writeText($w("#bugPrev").textContent); toast("Отчёт скопирован", "вставь его в сообщение автору") } catch { $w("#bugPrevBox").open = true }
      return;
    }
    const b = e.target.closest("[data-bug-send]");
    if (!b || BUG.sending) return;
    if ($w("#bugText").value.trim().length < 5) { note("Напиши хотя бы пару слов о том, что случилось."); $w("#bugText").focus(); return }
    BUG.sending = true; b.disabled = true; b.textContent = "Отправляю…"; note("");
    try {
      await api("/api/report/send", fields());
      close();
      toast("Отчёт отправлен — спасибо!", "Автор получит его в Telegram");
    } catch (err) {
      note("Не отправилось: " + err.message + ". Можно скопировать отчёт и отправить автору самому.");
      $w("[data-bug-copy]").hidden = false;
    }
    BUG.sending = false; b.disabled = false; b.textContent = "Отправить";
  });
  preview();
  setTimeout(() => $w("#bugText").focus(), 30);
}

document.addEventListener("click", e => {
  const a = e.target.closest("#bugBtn,[data-bug]");
  if (!a) return;
  e.preventDefault(); e.stopPropagation();
  bugReport(a.dataset.bug ? {error: a.dataset.bug} : {});
}, true);

// ---------- что-то сломалось → сразу предложить отправить отчёт (не чаще раза в 10 минут и не больше 3 раз за запуск)
const BUGWATCH = {n: null, shown: 0, at: 0};
async function bugWatch(){
  try {
    const r = await api("/api/errors");
    if (BUGWATCH.n === null) BUGWATCH.n = r.n;                  // старые ошибки (до открытия окна) не предлагаем
    else if (r.n > BUGWATCH.n) {
      BUGWATCH.n = r.n;
      if (BUGWATCH.shown < 3 && Date.now() - BUGWATCH.at > 600000 && store.get("bug.mute") !== "1") {
        BUGWATCH.shown++; BUGWATCH.at = Date.now();
        toast("В ScanHub что-то сломалось", "Нажми, чтобы отправить отчёт автору — ошибка уже подставлена", "warn", 15000,
              () => bugReport({error: r.last}));
      }
    }
  } catch {}
}
setInterval(bugWatch, 20000); setTimeout(bugWatch, 3000);

// ---------- ошибки окна → журнал ошибок ScanHub
let bugLogged = 0;
function bugLog(msg, src, line, stack){
  if (++bugLogged > 30) return;                         // зациклившаяся ошибка не должна заваливать журнал
  api("/api/clientlog", {msg: String(msg || "").slice(0, 800), src: String(src || "").replace(location.origin, ""), line,
                         stack: String(stack || "").replace(new RegExp(location.origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), "").slice(0, 1500)}).catch(() => {});
}
window.addEventListener("error", e => { if (e.message) bugLog(e.message, e.filename, e.lineno, e.error?.stack) });
window.addEventListener("unhandledrejection", e => {
  const r = e.reason;
  if (r?.api) return;                                   // ответ сервера с понятной ошибкой — не ошибка кода окна
  if (/Failed to fetch|NetworkError|Load failed|перезагружаю окно/i.test(String(r?.message || r))) return;   // связь с сервером оборвалась (выход, перезапуск) — не ошибка кода
  bugLog(r?.message || r, "promise", "", r?.stack);
});
