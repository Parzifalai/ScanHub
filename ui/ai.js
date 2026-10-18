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
    if (t.status === "error") return toast("Не получилось", t.error, "bad");
    toast("Готово", a.id === "disable_driver" ? "Драйвер отключён — перезагрузи компьютер, чтобы он выгрузился из памяти" : AI_ACT[a.id].label(a.arg), "ok", 8000);
    try { redrawPanels() } catch {}
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
  // ссылки: [текст](https://…) и голые https://… — открываются в браузере после подтверждения
  const links = s => s.replace(/\[([^\]]+)\]\((https:\/\/[^\s)]+)\)/g, '<a data-ai-link="$2" title="$2">$1</a>')
    .replace(/(^|[\s(])(https:\/\/[^\s<)]+?)(?=[.,;:!?]?(?:\s|$|\)|<))/g, '$1<a data-ai-link="$2">$2</a>');
  const inline = s => links(esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>"));
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
      <b>Сам он ничего не меняет</b> — только читает, ищет справки в интернете и советует. Действия — по твоей кнопке: «⚡ …» у совета или «✦ Сделай сам», тогда он выполнит предложенное и проверит результат.</p>
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
    ${aiWebHtml()}
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
    ${AI.cliWait === prov.id ? `<div class="sub">Открылось окно входа: войди в браузере и вернись сюда — ScanHub сам заметит вход.</div>` : ""}</div>`;
}
function aiWebHtml(){
  return `<div class="ai-files"><b>Интернет</b>
    <label class="switch"><input type="checkbox" id="aiWeb" ${AI.cfg?.web !== false ? "checked" : ""}> Разрешить искать в интернете
      <span class="sub">Помощник сможет узнать, что это за программа или ошибка, знают ли о проблеме другие, и найти официальный сайт, чтобы дать безопасную ссылку на скачивание. В запросы не попадают твои пути и имя. Для «Сделай сам» поиск всегда выключен.</span></label></div>`;
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
      питание, датчики, место, защиту, браузеры и то, что уже нашёл ScanHub, а при необходимости поищет в интернете${AI.cfg?.files === "off" ? "" : ", а ещё файлы и папки (кнопка «Файл…» или просто напиши путь)"}.
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
  else AI.msgs.push({role: "error", content: "Помощник не ответил: " + (j.error || "ошибка")});
  if (body.kind === "act") { try { redrawPanels() } catch {} }
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

// ---------- «✦ Есть ли тут важное?» перед удалением: помощник оценивает каждый пункт списка
// REVIEW[area] = {status, steps, answer, job, rows: [{id, label, path, size, v, why, extra}], marks: {id: row}, hidden}
// items — [{id, label, path?, size, note}]; path есть у настоящих файлов и папок — их можно удалить окном «Проверить и удалить»
const REVIEW = (() => { try { return JSON.parse(sessionStorage.getItem("scanhub.review") || "{}") } catch { return {} } })(), REVIEW_ITEMS = {};
// оценка переживает перезагрузку окна (сервер помнит, что разрешено удалить, до своего перезапуска)
const rvSave = () => { try { sessionStorage.setItem("scanhub.review", JSON.stringify(Object.fromEntries(Object.entries(REVIEW).filter(([, v]) => v.status === "done")))) } catch {} };
const REVIEW_TAG = /\[\[(?:оценка|найдено):[^\]]*\]\]/g;
const REVIEW_CHIP = {ok: ["chip-ok", "Можно удалить"], check: ["chip-warn", "Сначала посмотри"], keep: ["chip-bad", "Не удаляй"]};
const rvName = r => r.path ? r.path.split("\\").filter(Boolean).pop() : String(r.label || "");
const rvSize = r => r.size ? fmtB(r.size) : "";
// пункт внутри другой папки из того же списка (yara_x.pyd в build) — его размер уже учтён, а удалится он вместе с папкой
const rvNested = (x, rows) => !!x.path && rows.some(y => y !== x && y.path && x.path.toLowerCase().startsWith(y.path.toLowerCase().replace(/\\+$/, "") + "\\"));
function aiReviewBtn(area, items, label = "✦ Есть ли тут важное?"){
  REVIEW_ITEMS[area] = items;
  const r = REVIEW[area];
  if (!items.length) return "";
  return `<button class="small ai-btn" data-ai-review="${esc(area)}" ${r?.status === "running" ? "disabled" : ""}
    title="Помощник посмотрит каждый пункт: чей он, запущен ли, что внутри, а если непонятно — поищет в интернете. Скажет, что можно удалять смело, а что лучше оставить">${r?.status === "running" ? "✦ Помощник смотрит…" : esc(label)}</button>`;
}
function rvList(rows, area){
  return `<ul class="rv-list">${rows.map(r => `<li><b>${esc(rvName(r))}</b>${rvSize(r) ? ` <span class="sub-inline">${rvSize(r)}</span>` : ""}${r.extra ? ` <span class="chip-note" title="Этого не было в списке — помощник нашёл сам, когда смотрел папки">нашёл помощник</span>` : ""}
    — ${esc(r.why || "")}${r.path ? ` <a data-open="${esc(r.path)}" title="${esc(r.path)}">папка</a>` : ""}</li>`).join("")}</ul>`;
}
function aiReviewBox(area){
  const r = REVIEW[area];
  if (!r) return "";
  if (r.status === "running") return `<div class="note info ai-review"><div class="spin" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:-2px"></div>
    Помощник проверяет пункты — смотрит, чьи они, что внутри, и при необходимости ищет в интернете. Это 20–90 секунд.${r.steps?.length ? `<div class="sub">${esc(r.steps[r.steps.length - 1])}</div>` : ""}</div>`;
  if (r.status === "error") return `<div class="note warn ai-review">Помощник не смог проверить: ${esc(r.error || "ошибка")} <a data-ai-gear>Настройки помощника</a> · <a data-ai-review-close="${esc(area)}">Закрыть</a></div>`;
  const g = {ok: [], check: [], keep: []};
  r.rows.forEach(x => g[x.v]?.push(x));
  const sum = rows => rows.filter(x => !rvNested(x, rows)).reduce((a, x) => a + (x.size || 0), 0);
  const counts = `можно удалить — <b>${g.ok.length}</b>${sum(g.ok) ? ` (${fmtB(sum(g.ok))})` : ""}, сначала посмотри — <b>${g.check.length}</b>, не удаляй — <b>${g.keep.length}</b>`;
  if (r.hidden) return `<div class="note info ai-review rv-min"><b>✦ Оценка помощника:</b> ${counts}. <a data-ai-review-show="${esc(area)}">Показать</a> · <a data-ai-review-close="${esc(area)}">Убрать</a></div>`;
  const canDel = r.rows.some(x => x.path && x.v !== "keep");
  return `<div class="note info ai-review"><div class="rv-head"><span><b>✦ Помощник посмотрел:</b> ${counts}.</span>
      <span class="grow"></span><a data-ai-review-hide="${esc(area)}">Свернуть</a></div>
    ${aiMd(r.answer)}
    ${g.ok.length ? `<div class="rv-g rv-ok"><b>Можно удалить</b> — ${g.ok.length}${sum(g.ok) ? `, освободится ${fmtB(sum(g.ok))}` : ""}${rvList(g.ok)}</div>` : ""}
    ${g.check.length ? `<div class="rv-g rv-check"><b>Сначала посмотри</b> — ${g.check.length}${rvList(g.check)}</div>` : ""}
    ${g.keep.length ? `<details class="rv-g rv-keep"><summary><b>Не удаляй</b> — ${g.keep.length} (нажми, чтобы увидеть почему)</summary>${rvList(g.keep)}</details>` : ""}
    <div class="row-tools">${canDel ? `<button class="small primary" data-ai-review-del="${esc(area)}">✦ Проверить и удалить с помощью ИИ</button>` : g.ok.length ? `<span class="sub">Безопасное уже отмечено галочками — нажми кнопку удаления этого раздела ниже.</span>` : ""}
      <button class="small" data-ai-review-chat="${esc(area)}" title="Открыть помощника с этой оценкой — можно спросить подробнее про любой пункт">✦ Продолжить разговор</button></div></div>`;
}
function aiMark(area, id){
  const m = REVIEW[area]?.status === "done" && REVIEW[area].marks[id];
  if (!m) return "";
  const [cls, text] = REVIEW_CHIP[m.v];
  return ` <span class="${cls}" title="${esc(m.why)}">✦ ${text}</span>${m.why ? `<span class="sub ai-why">${esc(m.why)}</span>` : ""}`;
}
async function aiPoll(id, onStep){
  for (let fails = 0; ;) {
    await new Promise(res => setTimeout(res, 1000));
    let j;
    try { j = await api("/api/ai/job?id=" + id) } catch { if (++fails > 8) return {status: "error", error: "ScanHub перезапустился — попробуй ещё раз"}; continue }
    if (j.status !== "running") return j;
    onStep?.(j);
  }
}
async function aiReview(area){
  const items = REVIEW_ITEMS[area] || [];
  if (!items.length) return;
  if (!AI.cfg) await aiLoadCfg();
  if (!AI.cfg?.enabled) { toast("Сначала подключи ИИ-помощника", "это бесплатно — например, ключ Google Gemini", "info", 7000); return aiOpen(true) }
  const it = items.slice(0, 60);
  REVIEW[area] = {status: "running", steps: [], rows: [], marks: {}};
  redrawPanels();
  let j;
  try {
    const r = await api("/api/ai/ask", {kind: "review", area, items: it});
    REVIEW[area].job = r.id;
    j = await aiPoll(r.id, x => { REVIEW[area].steps = x.steps || []; redrawPanels() });
  } catch (e) { j = {status: "error", error: e.message} }
  const rv = REVIEW[area];
  if (j.status !== "done") { Object.assign(rv, {status: "error", error: j.error}); return redrawPanels() }
  rv.rows = j.review || [];
  rv.rows.forEach(x => { if (x.id != null) rv.marks[x.id] = x });
  Object.assign(rv, {status: "done", answer: String(j.answer || "").replace(REVIEW_TAG, "").replace(/\n{3,}/g, "\n\n").trim()});
  // сразу показываем: безопасное отмечаем, «не удаляй» снимаем (что отмечено — видно до нажатия «Удалить»)
  const set = REVIEW_SEL[area] && SEL[REVIEW_SEL[area]];
  if (set) for (const x of rv.rows) { if (x.id == null) continue; if (x.v === "ok" && !String(x.id).startsWith("d:")) set.add(x.id); if (x.v === "keep") set.delete(x.id) }
  if (!rv.rows.length) rv.answer += "\n\n(Помощник не поставил оценки пунктам — нажми ещё раз или выбери другую модель.)";
  rvToChat(area);
  rvSave(); redrawPanels();
  toast("Помощник проверил список", "оценка — над списком, метки — у каждого пункта", "info", 5000);
}
// в разговор — целиком, с оценкой каждого пункта: так «Продолжить разговор» знает, о чём речь (и после перезагрузки окна)
function rvToChat(area){
  const rv = REVIEW[area];
  if (!rv || rv.status !== "done" || AI.msgs.some(m => m.rv === area && m.job === rv.job)) return;
  const V = {ok: "можно удалить", check: "сначала посмотреть", keep: "не удалять"};
  AI.msgs.push({role: "user", content: "Проверь, нет ли важного: " + area, show: "✦ Есть ли тут важное: " + area, rv: area, job: rv.job},
    {role: "assistant", content: rv.answer + "\n\nОценка пунктов:\n" + rv.rows.map(x => `- ${x.path || x.label} (${rvSize(x) || "—"}): ${V[x.v]} — ${x.why}`).join("\n")});
}
// какой набор галочек (SEL) у каждого раздела очистки
const REVIEW_SEL = {"Мусор и кэши": "junk", "Место на диске": "big", "Дубликаты": "dups", "Остатки программы": "left", "Пустые папки": "empty",
  "Битые ярлыки": "lnk", "Старые драйверы": "drv"};

// быстрый вопрос помощнику без панели: ответ — строкой (для «Что это?» в окне удаления)
async function aiQuick(question){
  const r = await api("/api/ai/ask", {kind: "chat", messages: [{role: "user", content: question}]});
  const j = await aiPoll(r.id);
  if (j.status !== "done") throw new Error(j.error || "помощник не ответил");
  return j.answer;
}

// ---------- окно «Проверить и удалить с помощью ИИ»
async function aiReviewDelete(area){
  const rv = REVIEW[area];
  if (!rv?.job) return;
  const all = rv.rows.filter(x => x.path && x.v !== "keep"), rows = all.filter(x => !rvNested(x, all));
  const keep = rv.rows.filter(x => x.v === "keep").length;
  const on = new Set(rows.filter(x => x.v === "ok").map(x => x.path));
  const wrap = document.createElement("div");
  wrap.className = "mdl-back";
  const row = (x, i) => `<div class="rvd-row" data-i="${i}">
      <label class="rvd-main"><input type="checkbox" data-rvd="${i}" ${on.has(x.path) ? "checked" : ""}>
        <span><b>${esc(rvName(x))}</b> ${rvSize(x) ? `<span class="sub-inline">${rvSize(x)}</span>` : ""} <span class="${REVIEW_CHIP[x.v][0]}">✦ ${REVIEW_CHIP[x.v][1]}</span>
          <span class="sub">${esc(x.why || "")}</span></span></label>
      <div class="rvd-path"><a data-open="${esc(x.path)}" title="Открыть в Проводнике">${esc(x.path)}</a></div>
      <div class="rvd-acts"><button class="small" data-rvd-what="${i}" type="button">✦ Что это?</button><span class="rvd-res" id="rvdRes${i}"></span></div>
      <div class="rvd-what" id="rvdWhat${i}" hidden></div></div>`;
  const draw = () => {
    const tot = rows.filter(x => on.has(x.path)).reduce((a, x) => a + (x.size || 0), 0);
    wrap.querySelector("#rvdTot").textContent = `Выбрано: ${on.size}${tot ? ` · ${fmtB(tot)}` : ""}`;
    wrap.querySelector("[data-rvd-go]").disabled = !on.size;
  };
  wrap.innerHTML = `<div class="mdl xwide rvd" role="dialog" aria-modal="true" aria-labelledby="rvdT">
    <div class="mdl-top"><span class="mdl-ic">✦</span><h3 id="rvdT">Проверить и удалить с помощью ИИ</h3></div>
    <p>Отмечено то, что помощник считает безопасным. «Сначала посмотри» — не отмечено: нажми на путь, чтобы открыть папку, или «✦ Что это?», чтобы помощник рассказал подробнее.${keep ? ` Ещё ${keep} пунктов помощник советует не трогать — их здесь нет.` : ""}</p>
    <div class="rvd-list">${rows.map(row).join("")}</div>
    <div class="rvd-mode"><label><input type="radio" name="rvdMode" value="recycle" checked> В Корзину <span class="sub">— можно вернуть; место освободится после очистки Корзины (очень большие папки Windows может удалить сразу)</span></label>
      <label><input type="radio" name="rvdMode" value="permanent"> Удалить навсегда <span class="sub">— место освободится сразу, вернуть нельзя</span></label></div>
    <div class="note" id="rvdNote" hidden></div>
    <div class="mdl-btns"><span class="sub grow" id="rvdTot"></span><button data-rvd-x type="button">Закрыть</button><button class="danger" data-rvd-go type="button">Удалить выбранное</button></div></div>`;
  document.body.appendChild(wrap);
  draw();
  const close = () => { wrap.classList.add("out"); setTimeout(() => wrap.remove(), 140); document.removeEventListener("keydown", key, true) };
  const key = e => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close() } };
  document.addEventListener("keydown", key, true);
  const note = (html, kind = "info") => { const n = wrap.querySelector("#rvdNote"); n.hidden = !html; n.className = "note " + kind; n.innerHTML = html };
  const showResult = res => {
    const failed = res.failed || [];
    for (const d of res.done || []) {
      const i = rows.findIndex(x => x.path === d.path);
      if (i < 0) continue;
      on.delete(d.path);
      const el = wrap.querySelector(`.rvd-row[data-i="${i}"]`);
      el.classList.add("gone");
      el.querySelector(`#rvdRes${i}`).innerHTML = `<span class="chip-ok">✓ ${d.note ? esc(d.note) : res.permanent ? "удалено" : "в Корзине"}</span>`;
      el.querySelector("input").disabled = true;
    }
    for (const f of failed) {
      const i = rows.findIndex(x => x.path === f.path);
      if (i < 0) continue;
      wrap.querySelector(`#rvdRes${i}`).innerHTML = `<span class="chip-bad">не удалилось: ${esc(f.why)}</span>
        <div class="sub">${esc(f.how || "")}</div><div class="row-tools">
        ${f.kind === "admin" ? `<button class="small primary" data-rvd-admin="${i}" type="button">Удалить с правами администратора</button>` : ""}
        ${["admin", "busy"].includes(f.kind) ? `<button class="small" data-rvd-later="${i}" type="button">Удалить при перезагрузке</button>` : ""}
        <button class="small" data-rvd-help="${i}" data-why="${esc(f.why)}" type="button">✦ Как удалить?</button></div>`;
    }
    draw();
    note(`${res.done?.length ? `✓ Удалено: ${res.done.length}${res.freed ? ` · освободилось ${fmtB(res.freed)}${res.permanent ? "" : " (после очистки Корзины)"}` : ""}.` : ""}
      ${failed.length ? ` Не получилось: ${failed.length} — причина и что сделать написаны у каждого пункта.` : ""}`, failed.length ? "warn" : "info");
  };
  const run = async (paths, extra = {}) => {
    const permanent = wrap.querySelector('input[name="rvdMode"]:checked')?.value === "permanent";
    note(`<div class="spin" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:-2px"></div> Удаляю… ${extra.admin || extra.later ? "подтверди окно UAC (в нём будет «Python» — это ScanHub)" : ""}`);
    wrap.querySelectorAll("button").forEach(b => b.disabled = true);
    const t = await runTask("ai_delete", {job: rv.job, paths, permanent, ...extra});
    wrap.querySelectorAll("button").forEach(b => b.disabled = false);
    if (t.status === "error") return note(esc(t.error || "не получилось"), "bad");
    showResult(t.result || {});
    try { redrawPanels() } catch {}
  };
  wrap.addEventListener("change", e => { const i = e.target.dataset.rvd; if (i == null) return; e.target.checked ? on.add(rows[+i].path) : on.delete(rows[+i].path); draw() });
  wrap.addEventListener("click", async e => {
    const b = e.target.closest("button,[data-open]");
    if (!b || b.hasAttribute("data-open")) return;            // путь открывает папку общим обработчиком
    if (b.hasAttribute("data-rvd-x")) return close();
    if (b.hasAttribute("data-rvd-go")) {
      const permanent = wrap.querySelector('input[name="rvdMode"]:checked')?.value === "permanent";
      if (!await ask(`${permanent ? "Удалить навсегда" : "Отправить в Корзину"} выбранное (${on.size})?${permanent ? " Вернуть будет нельзя." : ""}`)) return;
      return run([...on]);
    }
    if (b.dataset.rvdAdmin) return run([rows[+b.dataset.rvdAdmin].path], {admin: true});
    if (b.dataset.rvdLater) return run([rows[+b.dataset.rvdLater].path], {later: true});
    if (b.dataset.rvdHelp) {
      const x = rows[+b.dataset.rvdHelp];
      close(); aiOpen();
      return aiAsk(`ScanHub не смог удалить «${x.path}»: ${b.dataset.why}. Как удалить это правильно и безопасно? Скажи по шагам, где это лежит и что нажать.`);
    }
    if (b.dataset.rvdWhat) {
      const i = +b.dataset.rvdWhat, x = rows[i], box = wrap.querySelector(`#rvdWhat${i}`);
      if (!box.hidden && box.dataset.done) { box.hidden = true; return }
      box.hidden = false; box.innerHTML = `<span class="sub">Помощник смотрит…</span>`; b.disabled = true;
      try {
        box.innerHTML = aiMd(await aiQuick(`Что это и можно ли это удалить: «${x.path}»${rvSize(x) ? ` (${rvSize(x)})` : ""}? Посмотри сведения о файле или папке${AI.cfg?.web ? ", при необходимости найди в интернете" : ""}. Ответь коротко: что это, чьё, что будет, если удалить, и вывод — удалять или нет.`));
        box.dataset.done = "1";
      } catch (err) { box.innerHTML = `<span class="sub">${esc(err.message)}</span>` }
      b.disabled = false;
    }
  });
}

// ---------- события
document.addEventListener("click", async e => {
  const l = e.target.closest("[data-ai-link]");
  if (!l) return;
  e.preventDefault(); e.stopPropagation();
  const url = l.dataset.aiLink;
  if (!await ask(`Открыть ссылку в браузере?\n${url}\n\nЕё дал ИИ-помощник — проверь, что адрес похож на сайт программы.`)) return;
  api("/api/link", {url, ai: true}).catch(err => toast("Не открылось", err.message, "warn"));
}, true);
document.addEventListener("click", async e => {
  const rv = e.target.closest("[data-ai-review],[data-ai-review-hide],[data-ai-review-show],[data-ai-review-close],[data-ai-review-del],[data-ai-review-chat]");
  if (!rv) return;
  e.preventDefault(); e.stopPropagation();
  const d = rv.dataset;
  if (d.aiReviewHide) { REVIEW[d.aiReviewHide].hidden = true; rvSave(); return redrawPanels() }
  if (d.aiReviewShow) { REVIEW[d.aiReviewShow].hidden = false; rvSave(); return redrawPanels() }
  if (d.aiReviewClose) { delete REVIEW[d.aiReviewClose]; rvSave(); return redrawPanels() }
  if (d.aiReviewDel) return aiReviewDelete(d.aiReviewDel);
  if (d.aiReviewChat) { rvToChat(d.aiReviewChat); await aiOpen(); const t = $("#aiText"); if (t) { t.placeholder = "Спроси про любой пункт: «а что за папка npm-cache?», «как удалить модель Ollama?»…"; t.focus() } return }
  return aiReview(d.aiReview);
}, true);
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
