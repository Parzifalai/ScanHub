// ============================================================ 2.4: история чатов ИИ-агента и его память
// Чаты хранятся только на этом компьютере (data/ai_chats). На всё окно — колонка слева, как в чат-программах;
// панелью сбоку — список поверх разговора по кнопке «История». Названия чатов агент придумывает сам в первом ответе.
AI.chatId = null; AI.chatTitle = ""; AI.chats = []; AI.chatQ = "";
const AI_HIST_ICON = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1"/><path d="M3.5 4.5v4h4"/><path d="M12 7.5V12l3 2"/></svg>`;
const AI_PEN = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/></svg>`;
const AI_BIN = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>`;
const AI_PIN = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 4h6l-1 6 3 3H7l3-3z"/><path d="M12 13v7"/></svg>`;
const AI_PLUS = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>`;

// колонка на всё окно по умолчанию скрыта — открывается кнопкой «История» и запоминается; список сбоку — только по кнопке
const aiHistWide = () => document.body.classList.contains("ai-full") && innerWidth >= 1100;
function aiHistOn(){ return aiHistWide() ? store.get("aiHist") === "1" : !!AI.histPop }
function aiHistToggle(force){
  if (aiHistWide()) store.set("aiHist", (force ?? !aiHistOn()) ? "1" : "0");
  else AI.histPop = force ?? !AI.histPop;
  aiHistPaint();
  if (aiHistOn()) { aiChatsLoad(); setTimeout(() => $("#aiHistQ")?.focus({preventScroll: true}), 60) }
}

function aiHistEl(){
  const p = aiPanel();
  let h = p.querySelector("#aiHist");
  if (h) return h;
  h = document.createElement("nav");
  h.id = "aiHist"; h.className = "ai-hist"; h.setAttribute("aria-label", "История чатов");
  h.innerHTML = `<div class="ai-hist-top"><b>Чаты</b><span class="grow"></span>
      <button class="ai-ib" type="button" data-ai-hist-new title="Новый разговор" aria-label="Новый разговор">${AI_PLUS}</button>
      <button class="ai-ib ai-hist-x" type="button" data-ai-hist-close title="Скрыть историю" aria-label="Скрыть историю">✕</button></div>
    <label class="ai-hist-q"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/></svg>
      <input id="aiHistQ" type="search" placeholder="Поиск по чатам" autocomplete="off" spellcheck="false"></label>
    <div class="ai-hist-list" id="aiHistList"></div>`;
  p.prepend(h);
  // кнопка «История» в шапке — рядом с «Новый разговор»
  const nw = p.querySelector("#aiNew");
  if (nw && !p.querySelector("#aiHistBtn")) nw.insertAdjacentHTML("beforebegin", `<button class="ai-ib" id="aiHistBtn" type="button" title="История чатов" aria-label="История чатов">${AI_HIST_ICON}</button>`);
  return h;
}
function aiHistPaint(){
  const p = aiPanel(), h = aiHistEl(), on = aiHistOn() && !AI.setup;
  p.classList.toggle("hist-col", on && aiHistWide());
  p.classList.toggle("hist-pop", on && !aiHistWide());
  h.hidden = !on;
  p.querySelector("#aiHistBtn")?.classList.toggle("on", on);
  if (on) aiHistList();
}

const AI_DAY = 864e5;
function aiChatGroup(iso){
  const d = new Date(iso || 0), t = new Date(); t.setHours(0, 0, 0, 0);
  const diff = t - new Date(d.getFullYear(), d.getMonth(), d.getDate());
  return diff <= 0 ? "Сегодня" : diff <= AI_DAY ? "Вчера" : diff <= 7 * AI_DAY ? "За неделю" : diff <= 30 * AI_DAY ? "За месяц" : "Раньше";
}
function aiHistList(){
  const box = document.getElementById("aiHistList");
  if (!box) return;
  if (!AI.chats.length) {
    box.innerHTML = `<p class="ai-hist-empty">${AI.chatQ ? "Ничего не нашлось." : "Здесь появятся твои разговоры с агентом. Они хранятся только на этом компьютере."}</p>`;
    return;
  }
  let last = "", html = "";
  for (const c of AI.chats) {
    const g = c.pin ? "Закреплённые" : aiChatGroup(c.updated);
    if (g !== last) { html += `<div class="ai-hist-g">${esc(g)}</div>`; last = g }
    html += `<div class="ai-hist-it${c.id === AI.chatId ? " on" : ""}" data-id="${esc(c.id)}">
      <button class="ai-hist-open" type="button" data-ai-chat="${esc(c.id)}" title="${esc(c.title)}">${c.ctx ? `<span class="ai-hist-ctx" title="Разговор о проверке">✦</span>` : ""}<span class="t">${esc(c.title)}</span></button>
      <span class="ai-hist-acts"><button class="ai-ib" type="button" data-ai-chat-pin="${esc(c.id)}" title="${c.pin ? "Открепить" : "Закрепить сверху"}" aria-label="${c.pin ? "Открепить" : "Закрепить"}"${c.pin ? ' class="on"' : ""}>${AI_PIN}</button>
        <button class="ai-ib" type="button" data-ai-chat-ren="${esc(c.id)}" title="Переименовать" aria-label="Переименовать">${AI_PEN}</button>
        <button class="ai-ib" type="button" data-ai-chat-del="${esc(c.id)}" title="Удалить чат" aria-label="Удалить чат">${AI_BIN}</button></span></div>`;
  }
  box.innerHTML = html;
}
async function aiChatsLoad(){
  try { AI.chats = (await api("/api/ai/chats" + (AI.chatQ ? "?q=" + encodeURIComponent(AI.chatQ) : ""))).chats || [] } catch { AI.chats = [] }
  if (aiHistOn()) aiHistList();
}

// сохранить текущий разговор (после вопроса и после ответа); разговор без вопросов человека не сохраняем
let aiSaving = Promise.resolve();
function aiSaveChat(autoTitle){
  const msgs = AI.msgs.filter(m => m.role !== "error" || m.content);
  if (!msgs.some(m => m.role === "user")) return aiSaving;
  const body = {id: AI.chatId, msgs, ...(AI.ctx ? {ctx: AI.ctx} : {}), ...(autoTitle ? {auto_title: autoTitle} : {})};
  aiSaving = aiSaving.then(async () => {
    body.id = AI.chatId;                                      // первое сохранение выдаёт номер — следующие идут в тот же чат
    try { const r = await api("/api/ai/chat", body); AI.chatId = r.id; AI.chatTitle = r.title; aiChatsLoad() } catch {}
  });
  return aiSaving;
}
async function aiChatOpen(id){
  if (AI.job?.status === "running") return toast("Агент ещё отвечает", "дождись ответа или нажми «Остановить»", "info", 5000);
  try {
    const c = await api("/api/ai/chat?id=" + encodeURIComponent(id));
    AI.chatId = c.id; AI.chatTitle = c.title || ""; AI.msgs = c.msgs || []; AI.ctx = c.ctx || null; AI.setup = false;
    if (!aiHistWide()) AI.histPop = false;
    const b = aiPanel().querySelector("#aiBody"); if (b) b._chat = null;          // другой разговор — перерисовать целиком
    aiRender();
    setTimeout(() => $("#aiText")?.focus({preventScroll: true}), 50);
  } catch (e) { toast("Не открылся", e.message, "warn"); aiChatsLoad() }
}
function aiChatNew(){
  if (AI.job?.status === "running") return;
  AI.msgs = []; AI.ctx = null; AI.chatId = null; AI.chatTitle = ""; AI.setup = false;
  if (!aiHistWide()) AI.histPop = false;
  aiRender();
  setTimeout(() => $("#aiText")?.focus({preventScroll: true}), 50);
}
function aiChatRename(id){
  const it = document.querySelector(`.ai-hist-it[data-id="${CSS.escape(id)}"]`), c = AI.chats.find(x => x.id === id);
  if (!it || !c) return;
  it.classList.add("edit");
  it.querySelector(".ai-hist-open").outerHTML = `<input class="ai-hist-ren" value="${esc(c.title)}" maxlength="90" aria-label="Название чата">`;
  const inp = it.querySelector(".ai-hist-ren");
  inp.focus(); inp.select();
  let done = false;
  const finish = async save => {
    if (done) return; done = true;
    const t = inp.value.trim();
    if (save && t && t !== c.title) { try { await api("/api/ai/chat_edit", {id, title: t}); if (id === AI.chatId) AI.chatTitle = t } catch (e) { toast("Не переименовалось", e.message, "warn") } }
    aiChatsLoad();
  };
  inp.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); finish(true) } if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); finish(false) } });
  inp.addEventListener("blur", () => finish(true));
}

document.addEventListener("click", async e => {
  const t = e.target;
  if (t.closest("#aiHistBtn")) { e.preventDefault(); e.stopPropagation(); return aiHistToggle() }
  if (!t.closest("#aiHist")) {
    if (AI.histPop && !t.closest("#aiPanel")) { AI.histPop = false; aiHistPaint() }
    return;
  }
  const b = t.closest("button");
  if (!b) return;
  e.preventDefault(); e.stopPropagation();
  if (b.hasAttribute("data-ai-hist-close")) return aiHistToggle(false);
  if (b.hasAttribute("data-ai-hist-new")) return aiChatNew();
  if (b.dataset.aiChat) return aiChatOpen(b.dataset.aiChat);
  if (b.dataset.aiChatRen) return aiChatRename(b.dataset.aiChatRen);
  if (b.dataset.aiChatPin) { const c = AI.chats.find(x => x.id === b.dataset.aiChatPin); try { await api("/api/ai/chat_edit", {id: b.dataset.aiChatPin, pin: !c?.pin}) } catch {} return aiChatsLoad() }
  if (b.dataset.aiChatDel) {
    const id = b.dataset.aiChatDel, c = AI.chats.find(x => x.id === id);
    if (!await ask(`Удалить чат «${c?.title || "без названия"}»? Вернуть его будет нельзя.`, {ok: "Удалить", danger: true})) return;
    await api("/api/ai/chat_del", {id}).catch(() => {});
    if (id === AI.chatId) aiChatNew();
    return aiChatsLoad();
  }
}, true);
let aiQTimer;
document.addEventListener("input", e => {
  if (e.target.id !== "aiHistQ") return;
  clearTimeout(aiQTimer);
  aiQTimer = setTimeout(() => { AI.chatQ = e.target.value.trim(); aiChatsLoad() }, 220);
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && AI.histPop && !document.querySelector(".mdl-back")) { e.preventDefault(); e.stopPropagation(); AI.histPop = false; aiHistPaint() }
}, true);
addEventListener("resize", () => { if (!aiPanel().hidden) aiHistPaint() });

// ---------- настройки: память агента и история
AI.mem = null;
async function aiMemLoad(){ try { AI.mem = await api("/api/ai/memory") } catch { AI.mem = {memory: [], on: true} } if (AI.setup) aiRender() }
function aiMemHtml(){
  if (!AI.mem) { aiMemLoad(); return `<div class="ai-files"><b>Память агента</b><span class="sub">Загружаю…</span></div>` }
  const m = AI.mem;
  return `<div class="ai-files ai-mem"><b>Память агента</b>
    <label class="switch"><input type="checkbox" id="aiMemOn" ${m.on !== false ? "checked" : ""}> Помнить важное между разговорами
      <span class="sub">Агент сам записывает короткие заметки: какой у тебя компьютер, что уже чинили и чем кончилось, о чём ты просил помнить. Хранятся только на этом компьютере; паролей и личных данных он не записывает.</span></label>
    ${m.memory?.length ? `<ul class="ai-mem-list">${m.memory.map(x => `<li><span>${esc(x.text)}</span><span class="sub">${esc((x.t || "").slice(0, 10).split("-").reverse().join("."))}</span>
        <button class="ai-ib" type="button" data-ai-mem-del="${esc(x.id)}" title="Забыть" aria-label="Забыть заметку">✕</button></li>`).join("")}</ul>
      <div class="row-tools"><button class="small" type="button" data-ai-mem-all>Забыть всё</button></div>`
      : `<span class="sub">${m.on !== false ? "Пока пусто: агент запишет сюда важное, когда будет повод. Можно попросить: «запомни, что…»." : "Память выключена."}</span>`}</div>
    <div class="ai-files"><b>История чатов</b>
      <span class="sub">Разговоры хранятся только на этом компьютере, пока ты их не удалишь.</span>
      <div class="row-tools"><button class="small" type="button" data-ai-chats-wipe>Удалить всю историю чатов</button></div></div>`;
}
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-ai-mem-del],[data-ai-mem-all],[data-ai-chats-wipe]");
  if (!b) return;
  e.preventDefault(); e.stopPropagation();
  if (b.dataset.aiMemDel) { AI.mem = await api("/api/ai/memory", {id: b.dataset.aiMemDel}).catch(() => AI.mem); return aiRender() }
  if (b.hasAttribute("data-ai-mem-all")) {
    if (!await ask("Забыть все заметки агента? Он перестанет помнить, что знал о тебе и компьютере.", {ok: "Забыть всё", danger: true})) return;
    AI.mem = await api("/api/ai/memory", {all: true}).catch(() => AI.mem); return aiRender();
  }
  if (b.hasAttribute("data-ai-chats-wipe")) {
    if (!await ask("Удалить все разговоры с агентом? Вернуть их будет нельзя.", {ok: "Удалить всё", danger: true})) return;
    const r = await api("/api/ai/chat_del", {all: true}).catch(() => ({deleted: 0}));
    AI.chatId = null; AI.chatTitle = ""; aiChatsLoad();
    toast("История чатов удалена", `разговоров: ${r.deleted}`);
  }
}, true);
document.addEventListener("change", e => {
  if (e.target.id !== "aiMemOn") return;
  api("/api/ai/memory", {on: e.target.checked}).then(m => { AI.mem = m; if (AI.cfg) AI.cfg.memory = m.on; aiRender();
    toast(m.on ? "Память агента включена" : "Память агента выключена", m.on ? "" : "заметки сохранятся, но агент их не увидит") }).catch(err => toast("Не сохранилось", err.message, "warn"));
});

// ---------- 2.4: «Копировать» у блока кода в ответе агента
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-ai-copy]");
  if (!b) return;
  e.preventDefault(); e.stopPropagation();
  const code = b.closest(".ai-code")?.querySelector("code")?.textContent || "";
  try { await navigator.clipboard.writeText(code) }
  catch { const t = document.createElement("textarea"); t.value = code; document.body.appendChild(t); t.select(); document.execCommand("copy"); t.remove() }
  b.textContent = "Скопировано ✓"; setTimeout(() => { b.textContent = "Копировать" }, 1600);
}, true);
