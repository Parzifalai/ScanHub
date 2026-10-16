// ============================================================ ИИ-помощник
// «✦ Как решить» у находок ScanHub и чат «Спроси про свой ПК». Модель сама смотрит журналы через инструменты сервера,
// которые только читают. Провайдер и модель меняются в настройках помощника (⚙ в его панели).
const AI = {cfg: null, msgs: [], job: null, setup: false, models: [], modelsFor: "", note: "", busySetup: false, cli: {}};
const aiPlan = src => { const seen = new Set();
  return [...String(src || "").matchAll(/\[\[действие:([a-z_]+)(?::([^\]]+))?\]\]/g)].map(m => ({id: m[1], arg: (m[2] || "").trim()}))
    .filter(a => AI_ACT[a.id] && !seen.has(a.id + a.arg) && seen.add(a.id + a.arg)).slice(0, 6) };
const stripTags = s => String(s ?? "").replace(/<[^>]*>/g, " ").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();
function aiBtn(title, text = "", extra = {}){
  const data = JSON.stringify({title: stripTags(title).slice(0, 300), text: stripTags(text).slice(0, 1800), ...extra});
  return `<button class="small ai-btn" data-ai="${esc(data)}" title="Помощник посмотрит данные компьютера, коротко скажет, как решить, и предложит кнопку, если ScanHub может сделать это сам">✦ Как решить</button>`;
}

// кнопки, которые помощник может предложить в конце ответа: [[кнопка:ИМЯ]] → действие ScanHub (только из этого списка)
const AI_BTN = {clean: ["Очистка мусора", "go", "clean:junk"], disk: ["Что занимает место", "go", "disk:disk"], updates: ["Обновления программ", "go", "apps:winget"],
  uninstall: ["Удаление программ", "go", "apps:uninst"], drivers: ["Драйверы", "go", "health:drivers"], crashes: ["Сбои и ошибки", "go", "health:crash"],
  hw: ["Комплектующие", "go", "health:hw"], startup: ["Автозагрузка", "go", "speed:boot"], noise: ["Почему шумит", "go", "speed:noise"],
  memory: ["Оперативная память", "go", "speed:memory"], security: ["Защита Windows", "go", "privacy:security"], browsers: ["Браузеры", "go", "privacy:browsers"],
  quarantine: ["Карантин", "go", "scan:quar"], scan: ["Проверить файл или папку", "go", "scan:check"], deep: ["Глубокая проверка", "go", "scan:deep"],
  ultra: ["Ультра проверка", "go", "ultra"], scanners: ["Сканеры", "go", "tools"], sfc: ["Восстановить системные файлы", "launch", "sfc_repair"],
  wu: ["Windows Update", "launch", "wu"], wu_drivers: ["Драйверы из Windows Update", "launch", "wu_optional"], restore: ["Точки восстановления", "go", "privacy:restore"],
  runtimes: ["Компоненты для программ", "go", "health:runtimes"], game: ["Игровой режим", "go", "speed:game"], firewall: ["Брандмауэр", "go", "privacy:firewall"]};
// действия, которые помощник может предложить: [[действие:ИМЯ:ПАРАМЕТР]] → ScanHub выполняет после подтверждения.
// Сервер всё равно проверяет: в карантин — только найденное проверкой, драйвер — только уязвимый, программа — только из списка winget
const AI_ACT = {
  update_program: {label: a => `Обновить ${a}`, ask: a => `Обновить программу ${a}? ScanHub скачает установщик, проверит его на вирусы и поставит.`},
  disable_driver: {label: a => `Отключить драйвер ${a}`, ask: a => `Отключить драйвер ${a}? Он перестанет загружаться после перезагрузки; вернуть можно в глубокой проверке. Попросит права администратора.`},
  quarantine: {label: a => `В карантин ${String(a).split("\\").pop()}`, ask: a => `Убрать в карантин ${a}? Файл перестанет запускаться; вернуть можно в «Проверка на вирусы → Карантин».`},
  startup_off: {label: a => `Выключить из автозагрузки: ${a}`, ask: a => `Выключить «${a}» из автозагрузки? Программа останется установленной, просто не будет стартовать сама.`},
  security_on: {label: a => `Включить защиту: ${a}`, ask: a => `Включить защиту Windows «${a}»? Исходное состояние сохранится.`},
  restore_on: {label: () => "Включить точки восстановления", ask: () => "Включить защиту системы и создать точку восстановления? Попросит права администратора."},
  free_ram: {label: () => "Освободить память", ask: () => "Освободить оперативную память (как Mem Reduct)? Открытые программы не закроются."},
  sfc: {label: () => "Восстановить системные файлы", ask: () => "Запустить восстановление системных файлов (DISM + SFC) в окне администратора? 10–30 минут."},
  wu_drivers: {label: () => "Драйверы в Windows Update", ask: null},
};
function aiActions(src){
  const acts = [...String(src || "").matchAll(/\[\[действие:([a-z_]+)(?::([^\]]+))?\]\]/g)].map(m => ({id: m[1], arg: (m[2] || "").trim()})).filter(a => AI_ACT[a.id]);
  const seen = new Set();
  return acts.filter(a => !seen.has(a.id + a.arg) && seen.add(a.id + a.arg)).slice(0, 3)
    .map(a => `<button class="small primary" data-ai-act="${attr(a)}">⚡ ${esc(AI_ACT[a.id].label(a.arg))}</button>`).join("");
}
async function aiDoAction(a){
  const m = AI_ACT[a.id];
  if (!m) return;
  if (m.ask && !await ask(m.ask(a.arg))) return;
  try {
    if (a.id === "update_program") { await api("/api/updates", {ids: [a.arg]}); go("apps", "winget"); return toast("Обновление запущено", "ScanHub проверит установщик на вирусы и поставит") }
    if (a.id === "sfc") return api("/api/launch", {what: "sfc_repair"});
    if (a.id === "wu_drivers") return api("/api/launch", {what: "wu_optional"});
    let name, args;
    if (a.id === "disable_driver") [name, args] = ["driver_disable", {service: a.arg.replace(/\.sys$/i, "").split("\\").pop()}];   // модель иногда пишет имя файла
    if (a.id === "quarantine") [name, args] = ["quarantine", {files: [{path: a.arg, name: "по совету помощника", engine: "помощник"}]}];
    if (a.id === "security_on") [name, args] = ["security_apply", {ids: [a.arg]}];
    if (a.id === "restore_on") [name, args] = ["restore_enable", {}];
    if (a.id === "free_ram") [name, args] = ["mem_quick", {}];
    if (a.id === "startup_off") {
      const st = (await runTask("startup", undefined, true)).result || {};
      const it = (st.items || []).find(i => i.name.toLowerCase() === a.arg.toLowerCase()) || (st.items || []).find(i => i.name.toLowerCase().includes(a.arg.toLowerCase()));
      if (!it) return toast("Не нашёл такую запись автозагрузки", a.arg, "warn");
      [name, args] = ["startup_set", {id: it.id, enable: false}];
    }
    const t = await runTask(name, args);
    if (t.status === "error") toast("Не получилось", t.error, "bad");
  } catch (e) { toast("Не получилось", e.message, "bad") }
}

function aiButtons(src){
  const ids = [...String(src || "").matchAll(/\[\[(?:кнопка:)?([a-z_]+)\]\]/g)].map(m => m[1]).filter(id => AI_BTN[id]);
  return [...new Set(ids)].slice(0, 3).map(id => { const [label, kind, to] = AI_BTN[id];
    return `<button class="small${kind === "go" ? "" : " primary"}" ${kind === "go" ? `data-go-page="${to}"` : `data-ai-launch="${to}"`}>${esc(label)}</button>` }).join("");
}

// безопасный мини-Markdown: сначала экранируем всё, потом жирный, код, списки, абзацы
function aiMd(src){
  src = String(src || "").replace(/^\s*\[\[(?:кнопка:|действие:)?[a-z_]+(?::[^\]]+)?\]\]\s*$/gm, "").replace(/\[\[(?:кнопка:|действие:)?[a-z_]+(?::[^\]]+)?\]\]/g, "");
  const inline = s => esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
  const out = [], lines = String(src || "").replace(/\r/g, "").split("\n");
  let list = null;
  const close = () => { if (list) { out.push(`</${list}>`); list = null } };
  for (const raw of lines) {
    const l = raw.trimEnd();
    let m;
    if ((m = l.match(/^\s*\d+[.)]\s+(.*)/))) { if (list !== "ol") { close(); out.push("<ol>"); list = "ol" } out.push(`<li>${inline(m[1])}</li>`) }
    else if ((m = l.match(/^\s*[-*•]\s+(.*)/))) { if (list !== "ul") { close(); out.push("<ul>"); list = "ul" } out.push(`<li>${inline(m[1])}</li>`) }
    else if ((m = l.match(/^#{1,4}\s+(.*)/))) { close(); out.push(`<p><b>${inline(m[1])}</b></p>`) }
    else if (!l.trim()) close();
    else { close(); out.push(`<p>${inline(l)}</p>`) }
  }
  close();
  return out.join("");
}

async function aiLoadCfg(){ try { AI.cfg = await api("/api/ai/config") } catch {} return AI.cfg }
function aiPanel(){
  let p = document.getElementById("aiPanel");
  if (p) return p;
  p = document.createElement("aside");
  p.id = "aiPanel"; p.className = "ai-panel"; p.hidden = true; p.setAttribute("aria-label", "ИИ-помощник");
  p.innerHTML = `<div class="ai-head"><b>✦ ИИ-помощник</b><span class="sub" id="aiModel"></span><span class="grow"></span>
      <button class="small" id="aiNew" title="Начать заново">Новый</button><button class="small" id="aiGear" title="Модель и ключи">⚙</button><button class="small" id="aiClose" title="Закрыть">✕</button></div>
    <div class="ai-body" id="aiBody"></div>
    <form class="ai-input" id="aiForm"><button class="small" id="aiAttach" type="button" title="Выбрать файл или папку на компьютере — помощник посмотрит сведения о нём">Файл…</button><textarea id="aiText" rows="2" placeholder="Спроси про свой ПК: «почему ноутбук греется?», «почему вылетает игра?»…" spellcheck="true"></textarea>
      <button class="primary" id="aiSend">Спросить</button></form>`;
  document.body.appendChild(p);
  return p;
}
async function aiOpen(setup){
  const p = aiPanel();
  p.hidden = false;
  if (!AI.cfg) await aiLoadCfg();
  if (setup || !AI.cfg?.enabled) AI.setup = true;
  aiRender();
  if (!AI.setup) setTimeout(() => $("#aiText")?.focus(), 50);
}
function aiClose(){ aiPanel().hidden = true }

function aiProviderName(id){ return (AI.cfg?.providers || []).find(p => p.id === id)?.name.split(" —")[0] || id }
function aiRender(){
  const p = aiPanel(), body = p.querySelector("#aiBody");
  p.querySelector("#aiModel").textContent = AI.cfg?.enabled ? `${aiProviderName(AI.cfg.provider)} · ${AI.cfg.model === "auto" ? "по подписке" : AI.cfg.model}${AI.cfg.agent ? " · агент" : ""}` : "не настроен";
  p.querySelector("#aiForm").hidden = AI.setup;
  body.innerHTML = AI.setup ? aiSetupHtml() : aiChatHtml();
  body.scrollTop = body.scrollHeight;
}

// ---------- настройки: провайдер, ключ, модель
function aiSetupHtml(){
  const c = AI.cfg || {providers: []}, sel = AI.pick || c.provider || "";
  const prov = c.providers.find(x => x.id === sel);
  return `<div class="ai-setup">
    <p>Помощник объясняет находки ScanHub и отвечает на вопросы «почему у меня…», сам заглядывая в журналы Windows, сбои, драйверы и питание.
      <b>Сам он ничего не меняет</b> — только читает и советует. Действия — по твоей кнопке: «⚡ …» у совета или «✦ Сделай сам», тогда он выполнит предложенное и проверит результат.</p>
    <div class="ai-provs">${c.providers.map(x => `<label class="ai-prov${x.id === sel ? " on" : ""}"><input type="radio" name="aiProv" value="${x.id}" ${x.id === sel ? "checked" : ""}>
      <span><b>${esc(x.name)}</b>${x.has_key ? ' <span class="chip-ok">ключ сохранён</span>' : ""}${x.id === sel ? `<span class="sub">${esc(x.hint)}</span>
      <a data-link="${esc(x.get)}">${esc(x.get_label)} →</a>` : ""}</span></label>`).join("")}</div>
    ${prov?.cli ? aiCliHtml(prov) : ""}
    ${prov ? `${prov.needs_key ? `<label class="ai-field">Ключ API ${esc(aiProviderName(prov.id))}
        <input type="password" id="aiKey" autocomplete="off" placeholder="${prov.has_key ? "ключ сохранён — вставь новый, чтобы заменить" : "вставь ключ сюда"}"></label>` : ""}
      <label class="ai-field">Модель
        <div class="row"><select id="aiModelSel">${AI.modelsFor === prov.id && AI.models.length ? AI.models.map(m => `<option value="${esc(m)}" ${m === (AI.modelPick || c.model) ? "selected" : ""}>${esc(m === "auto" ? "лучшая модель подписки (рекомендую)" : m)}</option>`).join("") : `<option value="">${prov.needs_key && !prov.has_key ? "сначала вставь ключ" : "нажми «Найти модели»"}</option>`}</select>
        <button class="small" id="aiFindModels" type="button" ${AI.busySetup ? "disabled" : ""}>Найти модели</button></div></label>
      <div class="row-tools"><button class="primary" id="aiSave" type="button" ${AI.busySetup ? "disabled" : ""}>Сохранить и проверить</button>
        ${c.enabled ? `<button id="aiOff" type="button">Выключить помощника</button>` : ""}${c.enabled ? `<button id="aiBack" type="button">К разговору</button>` : ""}</div>` : ""}
    ${AI.note ? `<div class="note ${AI.noteKind || "info"}">${esc(AI.note)}</div>` : ""}
    ${aiFilesHtml(c, prov)}
    ${prov?.cloud ? `<div class="sub">Перед отправкой ScanHub убирает имя пользователя, имя компьютера, личные пути, почту и ключи.${prov.needs_key ? " Ключ хранится на этом компьютере зашифрованным." : ""}</div>` : ""}
  </div>`;
}
// ---------- программы по подписке: Claude Code и Codex
function aiCliHtml(prov){
  const st = AI.cli[prov.id];
  return `<div class="ai-cli">${!st ? `<div class="sub">Проверяю программу…</div>`
    : `<div class="note ${st.connected ? (st.method === "api" ? "warn" : "info") : "warn"}">${esc(st.message)}</div>`}
    <div class="row-tools">${st && st.installed && !st.connected ? `<button class="primary small" data-ai-cli-login="${prov.id}" type="button">Войти</button>` : ""}
      ${st && !st.installed ? `<button class="small" data-link="${esc(prov.get)}" type="button">${esc(prov.get_label)}</button>` : ""}
      <button class="small" data-ai-cli-check="${prov.id}" type="button">Проверить</button></div>
    ${AI.cliWait === prov.id ? `<div class="sub">Открылось окно входа: войди в браузере и вернись сюда — ScanHub сам заметит вход.</div>` : ""}
    <label class="switch"><input type="checkbox" id="aiWeb" ${AI.cfg?.web !== false ? "checked" : ""}> Разрешить искать в интернете
      <span class="sub">Для справок: что это за программа, что значит код ошибки, есть ли у других такая проблема. В запросы не попадают твои пути и имя. Для «Сделай сам» поиск всегда выключен.</span></label></div>`;
}
async function aiCliCheck(id, action){
  try { AI.cli[id] = await api("/api/ai/cli", {provider: id, ...(action ? {action} : {})}) } catch (e) { AI.cli[id] = {installed: false, connected: false, message: e.message} }
  if (!AI.setup) return;
  aiRender();
  if (AI.cli[id]?.connected && AI.modelsFor !== id) aiFindModels();
}
// ---------- доступ к файлам на компьютере
const AI_FILES = [
  ["off", "Не смотреть файлы", "Только журналы Windows и то, что нашёл ScanHub."],
  ["meta", "Сведения о файлах", "Имя, размер, даты, цифровая подпись, издатель, откуда скачан, что сказали проверки. Содержимое не читает."],
  ["read", "Сведения и чтение текстовых файлов", "Плюс журналы программ, настройки, скрипты (.txt, .log, .ini, .bat…) — например, почему не запускается игра. Пароли, ключи, данные браузеров и мессенджеров не читает никогда."]];
function aiFilesHtml(c, prov){
  const cur = c.files || "meta";
  return `<div class="ai-files"><b>Файлы на компьютере</b>
    <div class="ai-provs">${AI_FILES.map(([id, name, hint]) => `<label class="ai-prov${id === cur ? " on" : ""}"><input type="radio" name="aiFiles" value="${id}" ${id === cur ? "checked" : ""}>
      <span><b>${esc(name)}</b><span class="sub">${esc(hint)}</span></span></label>`).join("")}</div>
    <div class="sub">Помощник ничего не удаляет, не запускает и не отправляет — только смотрит.${prov?.cloud || (!prov && c.providers?.find(x => x.id === c.provider)?.cloud) ? " С облачной моделью прочитанный текст уходит в неё — без имени пользователя, почты и ключей." : ""}</div></div>`;
}
async function aiFindModels(keyIn){
  const prov = AI.pick || AI.cfg?.provider;
  if (!prov) return;
  // ключ читаем ДО перерисовки: после неё поле ввода создаётся заново и пустое
  const key = (keyIn ?? $("#aiKey")?.value ?? AI.keyDraft ?? "").trim();
  AI.busySetup = true; AI.note = "Ищу доступные модели…"; AI.noteKind = "info"; aiRender();
  try {
    if (key) { AI.cfg = await api("/api/ai/config", {[prov + "_key"]: key}); AI.keyDraft = "" }
    const r = await api("/api/ai/models", {provider: prov});
    AI.models = r.models || []; AI.modelsFor = prov; AI.modelPick = AI.cfg?.provider === prov && AI.models.includes(AI.cfg.model) ? AI.cfg.model : r.default;
    AI.note = r.error ? r.error : AI.models.length ? `Найдено моделей: ${AI.models.length}. Выбрана рекомендуемая — можно поменять.` : "Моделей не найдено.";
    AI.noteKind = r.error || !AI.models.length ? "warn" : "info";
  } catch (e) { AI.note = e.message; AI.noteKind = "warn" }
  AI.busySetup = false; aiRender();
}
async function aiSave(){
  const prov = AI.pick || AI.cfg?.provider, model = $("#aiModelSel")?.value, key = ($("#aiKey")?.value || AI.keyDraft || "").trim();
  if (!prov) return;
  if (!model) { if (!AI.models.length) return aiFindModels(key); AI.note = "Выбери модель."; AI.noteKind = "warn"; return aiRender() }
  AI.busySetup = true; AI.note = "Проверяю связь с моделью…"; AI.noteKind = "info"; aiRender();
  try {
    AI.cfg = await api("/api/ai/config", {provider: prov, model, ...(key ? {[prov + "_key"]: key} : {})});
    const t = await api("/api/ai/test", {});
    if (t.ok && t.switched) {
      AI.cfg = t.cfg; AI.modelPick = t.switched; AI.setup = false;
      toast("ИИ-помощник подключён", `${t.was} сейчас перегружена — выбрана ${t.switched}`, "info", 8000);
    }
    else if (t.ok) { AI.note = ""; AI.setup = false; toast("ИИ-помощник подключён", `${aiProviderName(prov)} · ${model}`) }
    else { AI.note = "Не получилось: " + t.error; AI.noteKind = "warn" }
  } catch (e) { AI.note = e.message; AI.noteKind = "warn" }
  AI.busySetup = false; aiRender();
}

// ---------- разговор
const AI_SUGGEST = ["Что с моим компьютером не так?", "Почему ноутбук греется и шумит?", "Почему Windows медленно загружается?",
  "Почему вылетает игра?", "Что подозрительного в Загрузках?", "Что занимает место на диске C?", "Что лежит в карантине?",
  "Почему тормозит интернет?", "Почему ноутбук сам просыпается?"];
function aiChatHtml(){
  const j = AI.job;
  const msgs = AI.msgs.map(m => m.role === "user"
    ? `<div class="ai-msg ai-u">${esc(m.show || m.content)}</div>`
    : m.role === "error" ? `<div class="ai-msg ai-err">${esc(m.content)} <a data-ai-gear>Настройки помощника</a></div>`
    : `<div class="ai-msg ai-a">${aiMd(m.content)}${!m.act && aiPlan(m.content).length ? `<div class="ai-do"><button class="primary small" data-ai-do="${AI.msgs.indexOf(m)}" title="Помощник сам выполнит эти действия по очереди и проверит результат">✦ Сделай сам</button><span class="sub">${aiPlan(m.content).length > 1 ? `выполнит ${aiPlan(m.content).length} действия по очереди и проверит` : "выполнит и проверит"}; системные — с окном UAC</span></div>` : ""}${aiActions(m.content) || aiButtons(m.content) ? `<div class="row-tools ai-btns">${m.act ? "" : aiActions(m.content)}${aiButtons(m.content)}</div>` : ""}${m.finding ? `<div class="sub"><a data-ai-more="${esc(JSON.stringify(m.finding))}">Подробнее — что это и насколько серьёзно</a></div>` : ""}${m.cached ? `<div class="sub">ответ из памяти · <a data-ai-fresh="${esc(m.cached)}">спросить заново</a></div>` : ""}</div>`).join("");
  const run = j && j.status === "running" ? `<div class="ai-msg ai-a ai-run"><div class="spin"></div><div>${(j.steps || []).length ? `<ul class="ai-steps">${j.steps.map(s => `<li>${esc(s)}</li>`).join("")}</ul>` : `<span class="sub">думаю…</span>`}
      <button class="small" id="aiStop" type="button">Остановить</button></div></div>` : "";
  const empty = !AI.msgs.length && !run ? `<div class="ai-empty"><p>Спроси что угодно про этот компьютер — помощник сам посмотрит журналы Windows, сбои, драйверы,
      питание, датчики, место, защиту, браузеры и то, что уже нашёл ScanHub${AI.cfg?.files === "off" ? "" : ", а ещё файлы и папки (кнопка «Файл…» или просто напиши путь)"}.
      Или нажми «✦ Как решить» у любой находки — помощник коротко скажет, что делать, и предложит кнопку, если ScanHub может сделать это сам.</p><div class="ai-sug">${AI_SUGGEST.map(s => `<button class="small" data-ai-ask="${esc(s)}" type="button">${esc(s)}</button>`).join("")}</div></div>` : "";
  return empty + msgs + run;
}
async function aiStart(body, userMsg, finding = null){
  if (!AI.cfg?.enabled) { AI.setup = true; return aiRender() }
  if (AI.job?.status === "running") return;
  if (userMsg) AI.msgs.push(userMsg);
  AI.job = {status: "running", steps: []}; aiRender();
  try {
    const r = await api("/api/ai/ask", body);
    AI.job = {id: r.id, status: "running", steps: []};
  } catch (e) { AI.job = null; AI.msgs.push({role: "error", content: e.message}); return aiRender() }
  for (let fails = 0; ;) {
    await new Promise(r => setTimeout(r, 900));
    let j;
    try { j = await api("/api/ai/job?id=" + AI.job.id) }
    catch { if (++fails > 8) { AI.job = {status: "error", error: "ScanHub перезапустился посреди ответа — спроси ещё раз"}; break } continue }
    AI.job = j;
    if (j.status !== "running") break;
    if (!aiPanel().hidden) aiRender();
  }
  const j = AI.job; AI.job = null;
  if (j.status === "done") AI.msgs.push({role: "assistant", content: j.answer, cached: j.cached ? JSON.stringify(body.finding || null) : null, finding, act: body.kind === "act"});
  if (body.kind === "act") { try { redrawPanels() } catch {} }
  else AI.msgs.push({role: "error", content: "Помощник не ответил: " + (j.error || "ошибка")});
  aiRender();
  if (aiPanel().hidden && j.status === "done") toast("ИИ-помощник ответил", "открой панель помощника", "info", 6000, () => aiOpen());
}
async function aiDoIt(idx){
  const m = AI.msgs[idx], plan = aiPlan(m?.content);
  if (!plan.length) return;
  if (!await modal({title: "Сделать это самому помощнику?", icon: "✦", ok: "Сделай сам", cancel: "Отмена",
      html: `<p>Помощник выполнит по очереди только эти действия и проверит результат:</p><ul class="mdl-list">${plan.map(a => `<li>${esc(AI_ACT[a.id].label(a.arg))}</li>`).join("")}</ul>
        <p class="sub">Каждое действие идёт через те же проверки, что и кнопки ScanHub: только найденное проверкой, окно UAC для системных, и всё попадает в «Приватность и защита → Что изменил ScanHub» — там же можно отменить. Ничего сверх списка помощник сделать не может.</p>`})) return;
  aiStart({kind: "act", plan, context: m.content}, {role: "user", content: "Сделай сам", show: "✦ Сделай сам: " + plan.map(a => AI_ACT[a.id].label(a.arg)).join(", ")});
}
function aiAsk(text){
  text = String(text || "").trim();
  if (!text) return;
  const hist = AI.msgs.filter(m => m.role === "user" || m.role === "assistant").map(m => ({role: m.role, content: m.content}));
  aiStart({kind: "chat", messages: [...hist, {role: "user", content: text}]}, {role: "user", content: text});
}
function aiExplain(f, fresh = false, kind = "solve"){
  aiOpen();
  if (!AI.cfg?.enabled) return;
  const content = `${kind === "solve" ? "Как решить" : "Объясни подробнее"}: ${f.title}${f.text ? "\n" + f.text : ""}${f.source ? `\n(раздел ScanHub: ${f.source})` : ""}`;
  aiStart({kind, finding: f, fresh}, {role: "user", content, show: `${kind === "solve" ? "Как решить" : "Подробнее"}: ${f.title}`}, kind === "solve" ? f : null);
}

// ---------- события
document.addEventListener("click", async e => {
  const a = e.target.closest("[data-ai],[data-ai-ask],[data-ai-gear],[data-ai-fresh],[data-ai-launch],[data-ai-act],[data-ai-more],[data-ai-do],[data-ai-cli-login],[data-ai-cli-check],#aiTop,#aiClose,#aiGear,#aiNew,#aiStop,#aiFindModels,#aiSave,#aiOff,#aiBack,#aiAttach");
  if (!a) return;
  e.preventDefault(); e.stopPropagation();
  if (a.dataset.ai) { try { return aiExplain(JSON.parse(a.dataset.ai)) } catch { return } }
  if (a.dataset.aiAsk) { await aiOpen(); return aiAsk(a.dataset.aiAsk) }
  if (a.hasAttribute("data-ai-fresh")) { try { const f = JSON.parse(a.dataset.aiFresh); if (f) return aiExplain(f, true) } catch {} return }
  if (a.hasAttribute("data-ai-gear") || a.id === "aiGear") { AI.setup = true; AI.pick = AI.cfg?.provider || ""; aiRender();
    if (AI.cfg?.providers?.find(p => p.id === AI.pick)?.cli) aiCliCheck(AI.pick); return }
  if (a.id === "aiTop") return aiPanel().hidden ? aiOpen() : aiClose();
  if (a.id === "aiClose") return aiClose();
  if (a.id === "aiNew") { if (AI.job?.status !== "running") { AI.msgs = []; aiRender() } return }
  if (a.id === "aiStop") { if (AI.job?.id) api("/api/ai/stop", {id: AI.job.id}).catch(() => {}); return }
  if (a.dataset.aiAct) { try { return aiDoAction(JSON.parse(a.dataset.aiAct)) } catch { return } }
  if (a.hasAttribute("data-ai-do")) return aiDoIt(+a.dataset.aiDo);
  if (a.dataset.aiCliCheck) return aiCliCheck(a.dataset.aiCliCheck);
  if (a.dataset.aiCliLogin) {
    const id = a.dataset.aiCliLogin;
    await aiCliCheck(id, "login");
    AI.cliWait = id; aiRender();
    for (let i = 0; i < 100 && AI.cliWait === id && AI.setup; i++) {        // ждём вход до ~5 минут
      await new Promise(r => setTimeout(r, 3000));
      await aiCliCheck(id);
      if (AI.cli[id]?.connected) { AI.cliWait = null; toast("Аккаунт подключён", aiProviderName(id)); aiRender(); break }
    }
    return;
  }
  if (a.dataset.aiMore) { try { return aiExplain(JSON.parse(a.dataset.aiMore), false, "explain") } catch { return } }
  if (a.dataset.aiLaunch) return api("/api/launch", {what: a.dataset.aiLaunch}).catch(err => toast("Не удалось открыть", err.message, "bad"));
  if (a.id === "aiFindModels") return aiFindModels();
  if (a.id === "aiAttach") {
    if (AI.cfg?.files === "off") { toast("Помощник не смотрит файлы", "включи это в ⚙ → «Файлы на компьютере»", "info", 6000); return }
    const r = await api("/api/pick", {kind: "file"}).catch(() => ({}));
    if (!r.path) return;
    const t = $("#aiText");
    t.value = t.value.trim() ? `${t.value.trim()} «${r.path}»` : `Что это за файл и безопасен ли он: «${r.path}»`;
    t.focus(); return;
  }
  if (a.id === "aiSave") return aiSave();
  if (a.id === "aiBack") { AI.setup = false; AI.note = ""; return aiRender() }
  if (a.id === "aiOff") { AI.cfg = await api("/api/ai/config", {provider: "", model: ""}); AI.setup = true; AI.pick = ""; toast("ИИ-помощник выключен", ""); return aiRender() }
}, true);
document.addEventListener("change", e => {
  if (e.target.name === "aiProv") { AI.pick = e.target.value; AI.note = ""; AI.keyDraft = ""; aiRender();
    const pv = AI.cfg.providers.find(p => p.id === AI.pick);
    if (pv?.cli) { aiCliCheck(pv.id); return }
    if (!pv?.needs_key || pv?.has_key) aiFindModels() }
  if (e.target.id === "aiModelSel") AI.modelPick = e.target.value;
  if (e.target.id === "aiWeb") api("/api/ai/config", {web: e.target.checked}).then(c => { AI.cfg = c;
    toast(c.web ? "Поиск в интернете включён" : "Поиск в интернете выключен", "") }).catch(err => toast("Не сохранилось", err.message, "warn"));
  if (e.target.name === "aiFiles") api("/api/ai/config", {files: e.target.value}).then(c => { AI.cfg = c; aiRender();
    toast("Доступ к файлам изменён", AI_FILES.find(x => x[0] === c.files)?.[1] || "") }).catch(err => toast("Не сохранилось", err.message, "warn"));
});
document.addEventListener("input", e => { if (e.target.id === "aiKey") AI.keyDraft = e.target.value });   // не потерять вставленный ключ при перерисовке
document.addEventListener("submit", e => {
  if (e.target.id !== "aiForm") return;
  e.preventDefault();
  const t = $("#aiText"); aiAsk(t.value); t.value = "";
});
document.addEventListener("keydown", e => {
  if (e.target.id === "aiText" && e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#aiForm").requestSubmit() }
  if (e.key === "Escape" && !aiPanel().hidden && !document.querySelector(".mdl-back")) aiClose();
});
aiLoadCfg();
