// ============================================================ «ФИНАЛЬНЫЙ ВЫВОД» ИИ ПОСЛЕ ПРОВЕРОК
// После проверки файла, глубокой и ультра проверки встроенный агент сам читает сводку (ту же, что «Сводка для ИИ»),
// ScanHub ищет в интернете имя файла, его хэш и файлы с тревогами, и агент коротко говорит: можно открывать или нет.
// Под выводом — поле для вопроса: разговор продолжается в панели агента справа, и агент помнит эту проверку.

const VD = {};                 // ключ проверки → {status, job, steps, answer, error, scope, title, body}
const VD_LOOK = {
  "можно":     {cls: "ok",   ico: "✓", word: {check: "Можно открывать", deep: "Всё в порядке", ultra: "Всё в порядке"}},
  "осторожно": {cls: "warn", ico: "!", word: {check: "Лучше не открывать", deep: "Есть что проверить", ultra: "Есть что проверить"}},
  "нельзя":    {cls: "bad",  ico: "✕", word: {check: "Не открывай", deep: "Найдена угроза", ultra: "Найдена угроза"}},
};
const VD_SUM = {check: () => sumOpen("check", LAST_CHECK_SUM), deep: key => sumOpen("deep", {deep: VD[key]?.body?.deep}), ultra: () => sumOpen("ultra", {})};
const VD_ASK_HINT = {check: "Спросить про эту проверку: «что это за файл?», «как удалить безопасно?»",
                     deep: "Спросить про итог: «что из этого важно?», «как убрать находку?»",
                     ultra: "Спросить про итог: «с чего начать?», «что можно не трогать?»"};

const vdFresh = finished => !!finished && Date.now() - new Date(finished) < 60 * 60 * 1000;   // проверка закончилась меньше часа назад

function vdParse(ans){
  const src = String(ans || "");
  const m = /\[\[вывод:(можно|осторожно|нельзя)\]\]/.exec(src);
  const rest = src.replace(/\[\[вывод:[^\]]*\]\]/g, "").trim();
  const cut = rest.search(/\n\s*\n|\n\s*\*\*/);                 // первый абзац — «коротко», остальное — подробности
  return {v: m?.[1] || null, lead: cut > 0 ? rest.slice(0, cut).trim() : rest, more: cut > 0 ? rest.slice(cut).trim() : ""};
}

// что сейчас делает агент: шаги сервера → значок по смыслу
function vdStepIcon(s){
  s = String(s || "").toLowerCase();
  return /интернет|ищу|поиск/.test(s) ? "⌕" : /страниц|читаю/.test(s) ? "▤" : /журнал|сбо|событ/.test(s) ? "≡" : /думаю|вывод/.test(s) ? "✦" : "•";
}
function vdTrace(steps, live){
  const st = (steps || []).filter(Boolean);
  if (!st.length) return `<ol class="vd-trace"><li class="cur"><span class="vd-si">✦</span>читаю итог проверки…</li></ol>`;
  return `<ol class="vd-trace">${st.slice(-6).map((s, i, a) => `<li class="${live && i === a.length - 1 ? "cur" : ""}"><span class="vd-si">${vdStepIcon(s)}</span>${esc(s)}</li>`).join("")}</ol>`;
}

// карточка; key — какая проверка, body — что передать серверу ({scope, jobs, verdict, target, excluded} / {scope, deep} / {scope})
function vdCard(key, body){
  if (!key) return "";
  // одна и та же запись на всё время (итог перерисовывается часто, а ответ сервера пишется в эту запись)
  if (body) Object.assign(VD[key] ||= {}, {body: {...body}, scope: body.scope});
  const d = VD[key] ||= {}, scope = d.scope || "check";
  if (!AI.cfg) { aiLoadCfg().then(() => vdPaint(key)); return `<section class="vd" data-vd="${esc(key)}"></section>` }
  if (!AI.cfg.enabled) return `<section class="vd vd-off" data-vd="${esc(key)}">
      <div class="vd-head"><span class="vd-mark" aria-hidden="true">✦</span><b>Финальный вывод</b></div>
      <p class="vd-lead">Подключи ИИ-агента — он сам прочитает итог всех сканеров, поищет этот файл в интернете и коротко скажет, можно ли открывать. Это бесплатно, например с ключом Google Gemini.</p>
      <div class="vd-actions"><button class="small primary" data-vd-setup>Подключить агента</button></div></section>`;
  if (!d.status) {
    // сам — только после свежей проверки (старые итоги, открытые позже, — по кнопке) и если вывод не выключен в настройках
    if (AI.cfg.verdict === false || d.body?.auto === false) return `<section class="vd vd-idle" data-vd="${esc(key)}"><div class="vd-head"><span class="vd-mark" aria-hidden="true">✦</span><b>Финальный вывод</b>
      <span class="grow"></span><button class="small" data-vd-run="${esc(key)}">Спросить агента</button></div></section>`;
    setTimeout(() => vdRun(key), 0);
    d.status = "running"; d.steps = [];
    VD[key] = d;
  }
  const head = sub => `<div class="vd-head"><span class="vd-mark" aria-hidden="true">✦</span><b>Финальный вывод</b>${sub ? `<span class="sub">${sub}</span>` : ""}</div>`;
  if (d.status === "running") return `<section class="vd vd-run" data-vd="${esc(key)}" aria-live="polite">
      ${head("агент читает итог и ищет в интернете — обычно 20–60 секунд")}${vdTrace(d.steps, true)}</section>`;
  if (d.status === "error") return `<section class="vd vd-err" data-vd="${esc(key)}">${head()}
      <p class="vd-lead">Агент не смог сделать вывод: ${esc(d.error || "ошибка")}.</p>
      <div class="vd-actions"><button class="small" data-vd-redo="${esc(key)}">Попробовать ещё раз</button><button class="small" data-vd-gear>Настройки агента</button></div></section>`;
  const p = vdParse(d.answer), L = VD_LOOK[p.v] || {cls: "warn", ico: "?", word: {check: "Не уверен", deep: "Не уверен", ultra: "Не уверен"}};
  const web = (d.steps || []).filter(s => /^ищу в интернете/.test(s)).length;
  return `<section class="vd vd-${L.cls}" data-vd="${esc(key)}">
    ${head(web ? `прочитал итог всех сканеров · поискал в интернете (${web})` : "прочитал итог всех сканеров")}
    <div class="vd-verdict"><span class="vd-ico" aria-hidden="true">${L.ico}</span><span class="vd-word">${L.word[scope]}</span></div>
    <div class="vd-lead">${aiMd(p.lead)}</div>
    ${p.more ? `<details class="vd-more"><summary>${scope === "check" ? "Что нашёл в интернете и почему так" : "Что сделать и почему так"}</summary><div class="vd-more-body">${aiMd(p.more)}</div></details>` : ""}
    <form class="vd-ask" data-vd-ask="${esc(key)}"><input type="text" placeholder="${esc(VD_ASK_HINT[scope])}" aria-label="Вопрос агенту про эту проверку" autocomplete="off">
      <button class="primary small" type="submit">Спросить</button></form>
    <div class="vd-actions"><button class="small" data-vd-chat="${esc(key)}">Обсудить с агентом</button>
      <button class="small" data-vd-other="${esc(key)}" title="Сводка этой проверки для Claude, ChatGPT или Gemini — второе мнение">Спросить другой ИИ</button>
      <button class="small ghost" data-vd-redo="${esc(key)}">Проверить заново</button></div></section>`;
}

function vdPaint(key){
  document.querySelectorAll(`[data-vd="${CSS.escape(key)}"]`).forEach(el => {
    if (el.contains(document.activeElement) && document.activeElement.tagName === "INPUT") return;   // не сбиваем ввод
    const t = document.createElement("div");
    t.innerHTML = vdCard(key);
    if (t.firstElementChild) el.replaceWith(t.firstElementChild);
  });
}

async function vdRun(key){
  const d = VD[key];
  if (!d?.body) return;
  Object.assign(d, {status: "running", steps: [], answer: "", error: null, job: null});
  vdPaint(key);
  try { d.job = (await api("/api/ai/ask", {kind: "verdict", ...d.body})).id }
  catch (e) { Object.assign(d, {status: "error", error: e.message}); return vdPaint(key) }
  for (let fails = 0; ;) {
    await new Promise(r => setTimeout(r, 1000));
    let j;
    try { j = await api("/api/ai/job?id=" + d.job) }
    catch { if (++fails > 8) { Object.assign(d, {status: "error", error: "ScanHub перезапустился посреди ответа"}); break } continue }
    d.steps = j.steps || [];
    if (j.status !== "running") { Object.assign(d, {status: j.status === "done" ? "done" : "error", answer: j.answer, error: j.error}); break }
    vdPaint(key);
  }
  vdPaint(key);
  if (d.scope === "check" && typeof renderSimpleResult === "function" && key === "check:" + simpleBatch) renderSimpleResult();   // верхний итог зависит от ответа агента
  if (d.status === "done") {
    const p = vdParse(d.answer), L = VD_LOOK[p.v];
    if (L && document.hidden) toast("Финальный вывод: " + L.word[d.scope], stripTags(p.lead).slice(0, 140), L.cls === "bad" ? "err" : L.cls === "warn" ? "warn" : "ok", 9000);
  }
}

// разговор об этой проверке: в панели агента, с её сводкой и выводом в памяти
async function vdChat(key, question){
  const d = VD[key];
  if (!d?.job) return;
  if (AI.ctx?.job !== d.job) {
    const p = vdParse(d.answer), L = VD_LOOK[p.v];
    AI.chatId = null; AI.chatTitle = "";
    AI.ctx = {job: d.job, title: d.body?.title || {check: "проверка файла", deep: "глубокая проверка", ultra: "ультра проверка"}[d.scope], scope: d.scope};
    AI.msgs = [{role: "assistant", content: (L ? `**${L.word[d.scope]}.** ` : "") + String(d.answer || "").replace(/\[\[вывод:[^\]]*\]\]/g, "").trim(), verdict: true}];
  }
  await aiOpen();
  if (question) aiAsk(question);
}

document.addEventListener("submit", e => {
  const f = e.target.closest("[data-vd-ask]");
  if (!f) return;
  e.preventDefault();
  const q = f.querySelector("input").value.trim();
  if (!q) return f.querySelector("input").focus();
  f.querySelector("input").value = "";
  vdChat(f.dataset.vdAsk, q);
});
document.addEventListener("click", e => {
  const el = e.target.closest("[data-vd-run],[data-vd-redo],[data-vd-chat],[data-vd-other],[data-vd-setup],[data-vd-gear]");
  if (!el) return;
  const k = el.dataset.vdRun || el.dataset.vdRedo || el.dataset.vdChat || el.dataset.vdOther;
  if (el.dataset.vdRun || el.dataset.vdRedo) return vdRun(k);
  if (el.dataset.vdChat) return vdChat(k);
  if (el.dataset.vdOther) return VD_SUM[VD[k]?.scope || "check"](k);
  if (el.dataset.vdSetup !== undefined || el.dataset.vdGear !== undefined) return aiOpen(true);
});
