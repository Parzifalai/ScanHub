// ============================================================ Мастер первого запуска: «Подготовим ScanHub к работе»
// 1) скачать сканеры и базы (с согласием на базы опасных адресов Maltrail), 2) ключи онлайн-проверок с проверкой ключа,
// 3) ярлык и анонимная статистика. Подготовка идёт в фоне — пока она качается, человек вводит ключи.
// Показывается сам, пока мастер не пройден и чего-то не хватает; заново — ⚙ Настройки → «Мастер первого запуска».

const SETUP = {open: false, step: 0, info: null, started: false, keys: {}, links: true, usage: null};
const SETUP_KEYS = [
  ["virustotal_key", "VirusTotal", "virustotal", "Главный: сверяет файл с 70+ антивирусами. Бесплатно — 4 файла в минуту, 500 в день."],
  ["metadefender_key", "MetaDefender", "metadefender", "Ещё 20+ антивирусов, частично других, чем в VirusTotal."],
  ["filescan_key", "Filescan", "filescan", "Песочница OPSWAT: как файл ведёт себя при запуске."],
  ["hybrid_key", "Hybrid Analysis", "hybrid", "Песочница CrowdStrike: что файл делал в системе."],
];

async function setupCheck(){
  if (SETUP.checked || !TOOLS.length) return;
  SETUP.checked = true;
  try { SETUP.info = await api("/api/setup") } catch { return }
  if (SETUP.info.done) return;
  if (prepMissing().length || !SETUP.info.trails) return setupOpen();
  api("/api/setup/done", {}).catch(() => {});          // всё уже стоит (обновился со старой версии) — мастер не нужен
}

async function setupOpen(again){
  if (SETUP.open) return;
  if (again) try { SETUP.info = await api("/api/setup") } catch {}
  SETUP.open = true; SETUP.step = 0; SETUP.started = TASK.prepare?.status === "running";
  const w = document.createElement("div");
  w.id = "setupW"; w.className = "setup-back";
  document.body.appendChild(w);
  setupDraw();
}
function setupClose(){ SETUP.open = false; document.getElementById("setupW")?.remove() }

function setupProg(){ return `<div id="setupProgBox">${setupProgInner()}</div>` }
function setupProgInner(){
  const t = TASK.prepare;
  if (!SETUP.started && !t) return "";
  if (t?.status === "running") return `<div class="setup-prog"><div class="spin"></div><div style="flex:1;min-width:0"><b>Готовлю ScanHub…</b> <span class="sub">${esc(progOf(t.progress).t || "начинаю")}</span>${progHtml(t.progress, t.started) || progBar(0.02)}</div></div>`;
  if (t?.status === "done") { const r = t.result || {};
    return `<div class="setup-prog ${r.errors?.length ? "warn" : "ok"}">${r.errors?.length ? "!" : "✓"} <span><b>${r.errors?.length ? "Подготовка закончена, но не всё скачалось" : "Всё скачано и готово"}</b>
      ${r.errors?.length ? `<span class="sub">${r.errors.map(esc).join("; ")} — можно повторить потом кнопкой «Подготовить» на главной</span>` : ""}</span></div>` }
  if (t?.status === "error") return `<div class="setup-prog warn">! <span><b>Подготовка прервалась:</b> ${esc(t.error || "")}</span></div>`;
  return "";
}

function setupDraw(){
  const w = document.getElementById("setupW");
  if (!w) return;
  const st = SETUP.step, info = SETUP.info || {keys: {}};
  const dots = ["Скачать", "Ключи", "Готово"].map((n, i) => `<span class="${i === st ? "on" : i < st ? "done" : ""}">${i < st ? "✓" : i + 1}. ${n}</span>`).join("");
  let body = "";
  if (st === 0) body = `<h2>Подготовим ScanHub к работе</h2>
    <p>Чтобы проверки находили вирусы, ScanHub нужны сканеры и свежие базы. Он скачает их сам с официальных сайтов, проверит подписи и контрольные суммы. Это около 1 ГБ и 5–15 минут. Пока идёт загрузка, можно ввести ключи на следующем шаге.</p>
    <ul class="setup-list"><li><b>Антивирусы и сканеры:</b> ClamAV с базами, Atomdrift, HollowsHunter (код в процессах), MinerSearch (майнеры), Sigcheck (сертификаты), правила YARA</li>
      <li><b>Списки угроз:</b> уязвимые драйверы (LOLDrivers), опасные сайты (FMHY), вредоносные расширения браузеров</li></ul>
    <label class="setup-chk"><input type="checkbox" id="setupTrails" ${info.trails === false ? "checked" : "checked"}> <span><b>Базы опасных адресов Maltrail</b> (~12 МБ, 1,7 млн адресов вирусов и шпионов) — для проверки сети
      <span class="sub">Лицензия Maltrail разрешает их бесплатно для защиты своего компьютера. Отметка — твоё согласие с этим. Без них проверка сети смотрит только майнинг-пулы и файл hosts.</span></span></label>
    ${setupProg()}
    <div class="setup-btns"><button class="ghost" data-setup-skip>Пропустить</button><div class="grow"></div>
      <button class="primary" data-setup-go>${SETUP.started ? "Дальше" : "Начать подготовку"}</button></div>`;
  if (st === 1) body = `<h2>Ключи для онлайн-проверки <span class="sub-inline">по желанию, но очень советую</span></h2>
    <p>Без ключей ScanHub проверяет файлы на твоём компьютере. С ключами он ещё сверяет отпечаток файла (не сам файл) с базами десятков антивирусов. Ключи бесплатные: зарегистрируйся, скопируй ключ со страницы профиля и вставь сюда. Хватит одного VirusTotal.</p>
    ${setupProg()}
    <div class="setup-keys">${SETUP_KEYS.map(([k, name, tid, what]) => { const t = tool(tid), src = t?.source || {}, s = SETUP.keys[k];
      return `<div class="setup-key"><div class="setup-key-h"><b>${esc(name)}</b>${info.keys?.[k] || s?.ok ? ` <span class="chip-ok">ключ сохранён</span>` : ""}<div class="grow"></div>
          ${src.signup ? `<a data-link="${esc(src.signup)}">Регистрация →</a>` : ""}${src.key_page ? ` · <a data-link="${esc(src.key_page)}">Где взять ключ →</a>` : ""}</div>
        <div class="sub">${esc(what)}</div>
        <div class="row"><input type="password" id="sk-${k}" autocomplete="off" placeholder="${info.keys?.[k] ? "ключ уже есть — вставь новый, чтобы заменить" : "вставь ключ"}"><button class="small" data-setup-key="${k}">Проверить и сохранить</button></div>
        ${s ? `<div class="sub" style="color:var(--${s.ok === false ? "bad" : s.ok ? "ok" : "warn"})">${esc(s.text)}</div>` : ""}</div>` }).join("")}</div>
    <div class="setup-btns"><button class="ghost" data-setup-back>Назад</button><div class="grow"></div><button class="primary" data-setup-go>Дальше</button></div>`;
  if (st === 2) { const t = TASK.prepare, running = t?.status === "running";
    body = `<h2>${running ? "Почти готово — подготовка ещё идёт" : "Готово"}</h2>
    ${setupProg()}
    <label class="setup-chk"><input type="checkbox" id="setupLinks" ${SETUP.links ? "checked" : ""}> <span><b>Ярлык на рабочем столе и в меню «Пуск»</b><span class="sub">Чтобы открывать ScanHub в один клик.</span></span></label>
    <label class="setup-chk"><input type="checkbox" id="setupUsage" ${SETUP.usage ? "checked" : ""}> <span><b>Анонимная статистика запусков</b>
      <span class="sub">Раз в день сообщать автору, что ScanHub запущен: случайный номер копии, версия, язык. Без имён, файлов и находок. Помогает автору понять, сколько людей пользуется ScanHub.</span></span></label>
    <div class="note info" style="margin-top:10px">Дальше: на главной — «Ультра проверка», она проверит всё по очереди. ИИ-помощник (кнопка «✦ Помощник» вверху) настраивается отдельно, по желанию.</div>
    <div class="setup-btns"><button class="ghost" data-setup-back>Назад</button><div class="grow"></div>
      <button class="primary" data-setup-finish>${running ? "Открыть ScanHub — подготовка закончится сама" : "Открыть ScanHub"}</button></div>`; }
  const keep = {};                                   // не потерять вставленные, но ещё не сохранённые ключи
  w.querySelectorAll("input[id^='sk-']").forEach(i => { if (i.value) keep[i.id] = i.value });
  w.innerHTML = `<div class="setup" role="dialog" aria-modal="true" aria-label="Подготовка ScanHub"><div class="setup-top"><img src="/logo-small.svg" alt="" width="26" height="26"><b>ScanHub</b><div class="setup-dots">${dots}</div></div><div class="setup-body">${body}</div></div>`;
  for (const [id, v] of Object.entries(keep)) { const i = document.getElementById(id); if (i) i.value = v }
}

async function setupStartPrep(){
  if (SETUP.started) return;
  SETUP.started = true;
  const trails = document.getElementById("setupTrails")?.checked;
  runTask("prepare", {trails: !!trails}, true).then(() => { refresh(); const box = document.getElementById("setupProgBox"); if (box) box.innerHTML = setupProgInner();
    if (SETUP.step === 2) setupDraw() });
  // пока идёт подготовка — обновляем только полосу хода, чтобы не мешать вводу ключей
  const tick = () => { if (!SETUP.open) return; const box = document.getElementById("setupProgBox"); if (box) box.innerHTML = setupProgInner();
    if (TASK.prepare?.status === "running" || !TASK.prepare) setTimeout(tick, 1500) };
  setTimeout(tick, 800);
}

document.addEventListener("click", async e => {
  const b = e.target.closest("[data-setup-go],[data-setup-back],[data-setup-skip],[data-setup-key],[data-setup-finish],[data-setup-open]");
  if (!b) return;
  if (b.hasAttribute("data-setup-open")) { e.preventDefault(); document.getElementById("settings")?.close?.(); return setupOpen(true) }
  if (b.hasAttribute("data-setup-skip")) {
    if (!await ask("Пропустить подготовку? Проверки будут неполными, пока не скачаются сканеры и базы. Подготовить можно потом кнопкой на главной.", {ok: "Пропустить"})) return;
    api("/api/setup/done", {}).catch(() => {}); return setupClose();
  }
  if (b.hasAttribute("data-setup-go")) { if (SETUP.step === 0) setupStartPrep(); SETUP.step = Math.min(2, SETUP.step + 1); return setupDraw() }
  if (b.hasAttribute("data-setup-back")) { SETUP.step = Math.max(0, SETUP.step - 1); return setupDraw() }
  if (b.dataset.setupKey) {
    const k = b.dataset.setupKey, inp = document.getElementById("sk-" + k), v = inp?.value.trim();
    if (!v) { SETUP.keys[k] = {ok: false, text: "вставь ключ в поле"}; return setupDraw() }
    b.disabled = true; b.textContent = "Проверяю…";
    const r = await api("/api/setup/testkey", {key: k, value: v}).catch(err => ({ok: null, text: err.message}));
    if (r.ok !== false) { await api("/api/config", {[k]: v}); SETUP.info.keys[k] = true; r.text += " · сохранён" }
    SETUP.keys[k] = r;
    return setupDraw();
  }
  if (b.hasAttribute("data-setup-finish")) {
    SETUP.links = document.getElementById("setupLinks")?.checked;
    const usage = document.getElementById("setupUsage")?.checked;
    if (SETUP.links) runTask("app_links_create", {}, true).catch(() => {});
    try { USAGE = (await api("/api/usage", {on: !!usage})).on } catch {}
    await api("/api/setup/done", {}).catch(() => {});
    setupClose(); go("home");
    toast("ScanHub готов", TASK.prepare?.status === "running" ? "подготовка идёт — ход виден на главной" : "можно начинать проверку");
  }
});
document.addEventListener("change", e => { if (e.target.id === "setupLinks") SETUP.links = e.target.checked; if (e.target.id === "setupUsage") SETUP.usage = e.target.checked });
setInterval(setupCheck, 1500);
