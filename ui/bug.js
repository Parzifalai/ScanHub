// ============================================================ «Нашёл ошибку?» / «Предложить улучшение»
// Человек пишет, что случилось (или что улучшить), видит весь отчёт до отправки, отчёт уходит автору в Telegram (через посредник Cloudflare Worker).
// Плюс журнал ошибок окна: необработанные ошибки JavaScript уходят в data\errors.log, чтобы их можно было приложить к отчёту.

const BUG = {open: false, sending: false};

function bugPage(){
  try { const p = PAGES.find(x => x.id === PAGE); const t = (tabsOf(p) || []).find(x => x[0] === SUB); return [p?.t, t?.[1]].filter(Boolean).join(" → ") }
  catch { return "" }
}

async function bugReport(prefill = {}){
  if (BUG.open) return;
  BUG.open = true;
  const ctx = {page: prefill.page || bugPage(), error: prefill.error || "", kind: prefill.kind === "idea" && !prefill.error ? "idea" : "bug"};
  const wrap = document.createElement("div");
  wrap.className = "mdl-back";
  wrap.innerHTML = `<div class="mdl xwide bug-dlg" role="dialog" aria-modal="true" aria-labelledby="bugT">
    <div class="mdl-top"><span class="mdl-ic" id="bugIc">${icon("bug")}</span><h3 id="bugT">Написать автору ScanHub</h3></div>
    <div class="seg bug-kind" role="tablist"><button data-bug-kind="bug" role="tab">Нашёл ошибку</button><button data-bug-kind="idea" role="tab">Предложить улучшение</button></div>
    <p id="bugLead"></p>
    ${ctx.error ? `<div class="note bad">Ошибка на экране: ${esc(ctx.error)}</div>` : ""}
    <label class="bug-f"><span class="bug-h"><span id="bugTextH">Что случилось</span> <span class="sub">— обязательно</span></span>
      <textarea id="bugText" rows="4"></textarea></label>
    <label class="bug-f" id="bugStepsF"><span class="bug-h">Что делал перед этим <span class="sub">— по желанию, очень помогает</span></span>
      <textarea id="bugSteps" rows="3" placeholder="1. Открыл «Очистка» 2. Отметил «Временные файлы» 3. Нажал «Очистить»"></textarea></label>
    <div class="bug-f"><span class="bug-h">Снимки экрана <span class="sub">— по желанию, до трёх. Можно вставить Ctrl+V или перетащить сюда</span></span>
      <div class="bug-shots" id="bugShots"></div>
      <div class="row"><button class="small" type="button" data-bug-shot>Добавить снимок</button><input type="file" id="bugShotFile" accept="image/png,image/jpeg,image/webp" multiple hidden>
        <span class="sub" id="bugShotNote">Проверь, что на снимке нет личного: переписки, паролей, номеров карт.</span></div></div>
    <label class="bug-f"><span class="bug-h">Как с тобой связаться, если будут вопросы <span class="sub">— по желанию</span></span>
      <input id="bugContact" type="text" maxlength="120" placeholder="Telegram @ник или почта"></label>
    <label class="bug-chk"><input type="checkbox" id="bugTech" checked> Приложить версию ScanHub и Windows и раздел, где ты сейчас</label>
    <label class="bug-chk" id="bugLogsF"><input type="checkbox" id="bugLogs" checked> <span>Приложить журнал ошибок ScanHub <span class="sub" id="bugLogsN"></span>
      <span class="sub" style="display:block">Туда ScanHub сам записывает свои сбои: что упало и в каком месте кода. Без него автору сложнее найти причину. Твоих файлов и находок в нём нет.</span></span></label>
    <details class="bug-prev" id="bugPrevBox"><summary>Что уйдёт автору</summary><pre id="bugPrev" class="mono">…</pre>
      <div class="sub">Имя пользователя, имя компьютера, почта и ключи убраны. Больше ничего не отправляется: ни файлы, ни история проверок.</div></details>
    <div class="note warn" id="bugNote" hidden></div>
    <div class="mdl-btns"><button data-bug-x>Отмена</button><button class="ghost" data-bug-copy hidden>Скопировать отчёт</button><button class="primary" data-bug-send>Отправить</button></div>
  </div>`;
  document.body.appendChild(wrap);
  const $w = s => wrap.querySelector(s);
  const setKind = k => {
    ctx.kind = k;
    const idea = k === "idea";
    wrap.querySelectorAll("[data-bug-kind]").forEach(b => { b.classList.toggle("on", b.dataset.bugKind === k); b.setAttribute("aria-selected", b.dataset.bugKind === k) });
    $w("#bugIc").innerHTML = icon(idea ? "idea" : "bug");             // лампочка — идея, жук — ошибка (✦ — это ИИ-помощник)
    $w("#bugLead").textContent = idea ? "Чего не хватает в ScanHub, что неудобно или непонятно? Любая идея пригодится — автор читает всё. Ты увидишь сообщение целиком до отправки."
                                      : "Напиши, что пошло не так — отчёт уйдёт автору ScanHub. Ты увидишь его целиком до отправки.";
    $w("#bugTextH").textContent = idea ? "Что улучшить" : "Что случилось";
    $w("#bugText").placeholder = idea ? "Например: хочу, чтобы очистка запускалась по кнопке прямо с главной" : "Например: нажал «Очистить», крутится уже 10 минут и ничего не происходит";
    $w("#bugStepsF").hidden = idea;
    $w("#bugLogs").checked = !idea;
    if ($w("#bugPrevBox").open) preview();
  };
  const shots = [];
  const drawShots = () => {
    $w("#bugShots").innerHTML = shots.map((s, i) => `<span class="bug-shot"><img src="${s}" alt="Снимок ${i + 1}"><button type="button" data-bug-shot-x="${i}" title="Убрать">✕</button></span>`).join("");
    $w("[data-bug-shot]").disabled = shots.length >= 3;
    if ($w("#bugPrevBox").open) preview();
  };
  const addShots = async files => {
    for (const f of [...files].filter(f => /^image\//.test(f.type))) {
      if (shots.length >= 3) { note("Можно приложить не больше трёх снимков."); break }
      try { shots.push(await shrinkShot(f)); drawShots() } catch { note("Этот файл не похож на картинку.") }
    }
  };
  const fields = () => ({kind: ctx.kind, photos: shots, text: $w("#bugText").value, steps: ctx.kind === "idea" ? "" : $w("#bugSteps").value, contact: $w("#bugContact").value,
                         tech: $w("#bugTech").checked, logs: $w("#bugLogs").checked, page: ctx.page, error: ctx.error});
  const note = (t, kind = "warn") => { const n = $w("#bugNote"); n.hidden = !t; n.className = "note " + kind; n.textContent = t || "" };
  let ready = true;
  const preview = async () => {
    try { const r = await api("/api/report/preview", fields()); $w("#bugPrev").textContent = r.text; ready = r.ready;
      $w("#bugLogsN").textContent = r.log ? (r.log.n ? `— ${r.log.n} ${r.log.n === 1 ? "запись" : r.log.n < 5 ? "записи" : "записей"} с ${new Date(r.log.since).toLocaleDateString(LOC, {day: "numeric", month: "long"})}` : "— сейчас пуст, ошибок не было") : "";
      if (!ready) { note("Отправка отчётов в этой копии ScanHub не настроена. Скопируй отчёт и отправь автору сам."); $w("[data-bug-send]").hidden = true; $w("[data-bug-copy]").hidden = false } }
    catch (e) { $w("#bugPrev").textContent = "Не получилось собрать отчёт: " + e.message }
  };
  const close = () => { wrap.classList.add("out"); setTimeout(() => wrap.remove(), 140); BUG.open = false; document.removeEventListener("keydown", key, true) };
  const key = e => { if (e.key === "Escape" && !BUG.sending) { e.preventDefault(); e.stopPropagation(); close() } };
  document.addEventListener("keydown", key, true);
  $w("#bugPrevBox").addEventListener("toggle", e => { if (e.target.open) preview() });
  $w("#bugTech").addEventListener("change", () => { if ($w("#bugPrevBox").open) preview() });
  $w("#bugLogs").addEventListener("change", () => { if ($w("#bugPrevBox").open) preview() });
  $w("#bugShotFile").addEventListener("change", e => { addShots(e.target.files); e.target.value = "" });
  wrap.addEventListener("paste", e => { const f = [...(e.clipboardData?.files || [])]; if (f.length) { e.preventDefault(); addShots(f) } });
  wrap.addEventListener("dragover", e => { if ([...(e.dataTransfer?.items || [])].some(i => i.kind === "file")) { e.preventDefault(); e.stopPropagation() } }, true);
  wrap.addEventListener("drop", e => { if (e.dataTransfer?.files?.length) { e.preventDefault(); e.stopPropagation(); addShots(e.dataTransfer.files) } }, true);
  wrap.addEventListener("click", async e => {
    if (e.target === wrap || e.target.closest("[data-bug-x]")) { if (!BUG.sending) close(); return }
    if (e.target.closest("[data-bug-shot]")) { $w("#bugShotFile").click(); return }
    const sx = e.target.closest("[data-bug-shot-x]");
    if (sx) { shots.splice(+sx.dataset.bugShotX, 1); drawShots(); return }
    const kb = e.target.closest("[data-bug-kind]");
    if (kb) { setKind(kb.dataset.bugKind); $w("#bugText").focus(); return }
    if (e.target.closest("[data-bug-copy]")) {
      await preview();
      try { await navigator.clipboard.writeText($w("#bugPrev").textContent); toast("Отчёт скопирован", "вставь его в сообщение автору") } catch { $w("#bugPrevBox").open = true }
      return;
    }
    const b = e.target.closest("[data-bug-send]");
    if (!b || BUG.sending) return;
    if ($w("#bugText").value.trim().length < 5) { note(ctx.kind === "idea" ? "Напиши хотя бы пару слов." : "Напиши хотя бы пару слов о том, что случилось."); $w("#bugText").focus(); return }
    BUG.sending = true; b.disabled = true; b.textContent = "Отправляю…"; note("");
    try {
      await api("/api/report/send", fields());
      close();
      toast(ctx.kind === "idea" ? "Идея отправлена — спасибо!" : "Отчёт отправлен — спасибо!", ctx.kind === "idea" ? "Автор получит её в Telegram" : "Автор получит его в Telegram");
    } catch (err) {
      note("Не отправилось: " + err.message + ". Можно скопировать отчёт и отправить автору самому.");
      $w("[data-bug-copy]").hidden = false;
    }
    BUG.sending = false; b.disabled = false; b.textContent = "Отправить";
  });
  setKind(ctx.kind);
  preview();
  setTimeout(() => $w("#bugText").focus(), 30);
}

// снимок → JPEG не больше ~400 КБ и 1920 px по длинной стороне (так он гарантированно пройдёт в Telegram и не раздует отчёт)
async function shrinkShot(file){
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise((ok, bad) => { const i = new Image(); i.onload = () => ok(i); i.onerror = bad; i.src = url });
    let side = 1920, q = 0.85, out = "";
    for (let n = 0; n < 8; n++) {
      const k = Math.min(1, side / Math.max(img.naturalWidth, img.naturalHeight));
      const c = document.createElement("canvas");
      c.width = Math.max(1, Math.round(img.naturalWidth * k)); c.height = Math.max(1, Math.round(img.naturalHeight * k));
      const g = c.getContext("2d"); g.fillStyle = "#fff"; g.fillRect(0, 0, c.width, c.height); g.drawImage(img, 0, 0, c.width, c.height);
      out = c.toDataURL("image/jpeg", q);
      if (out.length * 0.75 <= 400 * 1024) break;
      if (q > 0.6) q -= 0.1; else side = Math.round(side * 0.8);
    }
    return out;
  } finally { URL.revokeObjectURL(url) }
}

document.addEventListener("click", e => {
  const a = e.target.closest("#bugBtn,[data-bug],[data-idea]");
  if (!a) return;
  e.preventDefault(); e.stopPropagation();
  bugReport(a.dataset.bug ? {error: a.dataset.bug} : a.hasAttribute("data-idea") ? {kind: "idea"} : {});
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
