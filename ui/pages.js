// ============================================================ НАВИГАЦИЯ: разделы слева, вкладки сверху
const PAGES = [
  {id: "home", ico: "home", t: "Главная"},
  {id: "ultra", ico: "ultra", t: "Ультра проверка"},
  {id: "scan", ico: "scan", t: "Проверка на вирусы",
   intro: "Проверить файл, папку, программу или весь компьютер. Сразу смотрят несколько антивирусов и наборов правил, а их находки ScanHub перепроверяет по цифровой подписи и VirusTotal, чтобы не пугать ложными тревогами.",
   tabs: [["check", "Проверка"], ["deep", "Глубокая проверка"], ["apps", "Проверить программу"], ["quar", "Карантин"], ["network", "Сеть", "dev"]]},
  {id: "clean", ico: "clean", t: "Очистка",
   intro: "Удаление того, что точно не нужно: временные файлы, кэши, следы удалённых программ. У каждого пункта написано, что это такое и что будет после очистки.",
   tabs: [["junk", "Мусор и кэши"], ["shortcuts", "Битые ярлыки"], ["drvstore", "Старые драйверы"], ["envpath", "Переменная PATH"]]},
  {id: "disk", ico: "disk", t: "Место на диске",
   intro: "Что занимает место: папки, типы файлов, самые большие файлы, одинаковые копии и пустые папки. Удалённое отсюда уходит в Корзину — его можно вернуть.",
   tabs: [["disk", "Что занимает место"], ["dups", "Дубликаты"], ["empty", "Пустые папки"]]},
  {id: "apps", ico: "apps", t: "Программы",
   intro: "Удаление программ вместе с остатками, лишние встроенные приложения Windows и обновления программ.",
   tabs: [["uninst", "Удаление программ"], ["debloat", "Встроенные приложения"], ["winget", "Обновления программ"]]},
  {id: "speed", ico: "speed", t: "Скорость",
   intro: "Что запускается вместе с Windows и замедляет загрузку, игровой режим, оперативная память и шум вентиляторов.",
   tabs: [["boot", "Автозагрузка"], ["game", "Игровой режим"], ["memory", "Оперативная память"], ["noise", "Почему шумит"], ["net", "Интернет"]]},
  {id: "privacy", ico: "privacy", t: "Приватность и защита",
   intro: "Что Windows отправляет о тебе, что программы добавили в меню правой кнопки, кого пускает брандмауэр и как откатить изменения.",
   tabs: [["privacy", "Приватность"], ["security", "Защита Windows"], ["browsers", "Браузеры"], ["ctx", "Контекстное меню"], ["firewall", "Брандмауэр"], ["restore", "Точки восстановления"], ["miners", "Защита от майнеров"], ["shred", "Шредер"], ["changes", "Что изменил ScanHub"]]},
  {id: "health", ico: "health", t: "Здоровье ПК", intro: "Общая проверка системы, сбои и их причины, компоненты для программ, предупреждения, устройства (клавиатура, мышь, микрофон, звук, камера), драйверы и комплектующие.",
   tabs: [["health", "Полная проверка"], ["crash", "Сбои и ошибки"], ["runtimes", "Компоненты для программ"], ["alerts", "Предупреждения"], ["devices", "Устройства"], ["drivers", "Драйверы"], ["hw", "Комплектующие"], ["history", "История"]]},
  {id: "phone", ico: "phone", t: "Телефон", intro: "Проверка Android-телефона по кабелю: следилки, приложения не из магазина, кто получил опасный доступ, обновления безопасности, батарея и память. На телефон ничего не ставится."},
  {id: "res", ico: "res", t: "Ресурсы", intro: "Нагрузка на процессор, память, видеокарту, сеть и диск за последние 5 минут — и какие программы её создают."},
  {id: "tools", ico: "tools", t: "Сканеры", dev: true, intro: "Все подключённые сканеры: версии, обновления, режимы запуска и технические подробности."},
  {id: "history", ico: "history", t: "История", intro: "Все проверки с результатами и журналами."},
];
const OLD_PANELS = {deep: ["scan", "deep"], apps: ["scan", "apps"], network: ["scan", "network"], cleanup: ["clean", "junk"],
  health: ["health", "health"], drivers: ["health", "drivers"], hw: ["health", "hw"], protect: ["privacy", "miners"],
  noise: ["speed", "noise"], autoruns: ["speed", "boot"]};
let PAGE = store.get("page") || "home", SUB = null;
const SUBS = (() => { try { return JSON.parse(store.get("subs") || "{}") } catch { return {} } })();
const pageOf = id => PAGES.find(p => p.id === id) || PAGES[0];
const tabsOf = p => (p.tabs || []).filter(t => t[2] !== "dev" || MODE === "dev");
const attr = o => esc(JSON.stringify(o));

function go(page, sub){
  const p = pageOf(page);
  if (p.dev && MODE !== "dev") { MODE = "dev"; store.set("mode", MODE); render() }
  PAGE = p.id;
  const tabs = tabsOf(p);
  SUB = tabs.some(t => t[0] === sub) ? sub : tabs.some(t => t[0] === SUBS[PAGE]) ? SUBS[PAGE] : (tabs[0]?.[0] || null);
  SUBS[PAGE] = SUB;
  store.set("page", PAGE); store.set("subs", JSON.stringify(SUBS));
  document.body.classList.remove("nav-open");
  showPage();
  window.scrollTo({top: 0});
}
function goPanel(name){
  const [p, s] = OLD_PANELS[name] || [(PAGES.find(x => (x.tabs || []).some(t => t[0] === name)) || PAGES[0]).id, name];
  go(p, s);
}
function viewFor(){
  if (PAGE === "home") return "home";
  if (PAGE === "scan" && SUB === "check") return "check";
  if (["tools", "res", "history"].includes(PAGE)) return PAGE;
  return "panel";
}
function showPage(){
  const p = pageOf(PAGE), v = viewFor(), tabs = tabsOf(p);
  if (p.dev && MODE !== "dev") return go("home");
  if (tabs.length && !tabs.some(t => t[0] === SUB)) SUB = tabs[0][0];
  for (const id of ["home", "check", "tools", "res", "history", "panel"]) $("#v-" + id).hidden = v !== id;
  $("#pageHead").innerHTML = PAGE === "home" ? "" : `<div class="page-h"><h2><span class="plate">${icon(p.ico)}</span>${esc(p.t)}</h2>${p.intro ? `<p>${esc(p.intro)}</p>` : ""}</div>
    ${tabs.length > 1 ? `<div class="tabs" role="tablist">${tabs.map(t => `<button role="tab" data-tab-go="${t[0]}" class="${t[0] === SUB ? "on" : ""}">${esc(t[1])}${tabCount(t[0]) ? ` <span class="cnt">${tabCount(t[0])}</span>` : ""}</button>`).join("")}</div>` : ""}`;
  renderNav();
  if (v === "panel") { prepPanel(SUB || PAGE); redrawPanels() }
  if (v === "tools") renderDev();
  if (v === "history") loadHistory();
  if (v === "home" || v === "check") renderSimple();
  if (v === "check") ensureTask("quarantine_list");
  if (v === "home") { prepHome(); renderTodo(); renderUltraCta() }
  if (M && (v === "res" || v === "home")) drawRes();          // сразу из уже собранных данных, не дожидаясь опроса
  pollMetrics();
}
const tabCount = id => id === "quar" ? (TASK.quarantine_list?.result?.items || []).length : 0;
function renderNav(){
  const q = (TASK.quarantine_list?.result?.items || []).length, game = TASK.game?.result?.active;
  const bad = TODO.filter(x => x.lvl === "bad").length, warn = TODO.filter(x => x.lvl === "warn").length;
  const uj = ULTRA.job, ub = uj?.status === "running" ? ["идёт", "ok"] : uj && !ULTRA.seen && (uj.stats?.threats || uj.stats?.bad) ? [uj.stats.threats || uj.stats.bad, uj.stats.threats ? "bad" : "warn"] : null;
  const badge = {home: bad ? [bad, "bad"] : warn ? [warn, "warn"] : null, scan: q ? [q, "", `В карантине файлов: ${q} — они обезврежены. Открыть: вкладка «Карантин»`] : null, speed: game ? ["игра", "ok"] : null, ultra: ub};
  $("#side").innerHTML = PAGES.filter(p => !p.dev || MODE === "dev").map(p => `<a class="nav${p.id === PAGE ? " on" : ""}" data-go="${p.id}" href="#">
      <span class="ico">${icon(p.ico)}</span><span class="t">${esc(p.t)}</span>${badge[p.id] ? `<span class="cnt ${badge[p.id][1]}"${badge[p.id][2] ? ` title="${esc(badge[p.id][2])}"` : ""}>${badge[p.id][0]}</span>` : ""}</a>`).join("") +
    "" ;
  // число на вкладках (сейчас — «Карантин») обновляется вместе с боковым меню
  document.querySelectorAll(".tabs [data-tab-go]").forEach(b => {
    const n = tabCount(b.dataset.tabGo), c = b.querySelector(".cnt");
    if (n && c) c.textContent = n; else if (n) b.insertAdjacentHTML("beforeend", ` <span class="cnt">${n}</span>`); else c?.remove();
  });
  $("#side").innerHTML += `<div class="side-foot">${MODE === "dev" ? "Режим «Разработчик»: видны пути, команды, коды выхода и консоль." : "Простой режим: только главное. Подробности — в режиме «Разработчик»."}<div style="margin-top:6px;opacity:.6">ScanHub ${esc(typeof VERSION === "string" ? VERSION : "")}</div>
    <div style="margin-top:6px"><a data-idea class="idea-link" title="Чего не хватает или что неудобно — автор читает всё">${icon("idea")}Предложить улучшение</a></div>
    <div class="langsw" data-noi18n><a data-lang="ru" class="${LANG === "ru" ? "on" : ""}">Русский</a> · <a data-lang="en" class="${LANG === "en" ? "on" : ""}">English</a></div></div>`;
}

// ============================================================ «Подготовить ScanHub»: всё, без чего проверки неполные
const PREP = {clamav: "ClamAV", atomscan: "Atomdrift", hollowshunter: "HollowsHunter", rootcerts: "Sigcheck", minersearch: "MinerSearch"};
function prepMissing(){
  const out = Object.entries(PREP).filter(([id]) => tool(id) && !tool(id).ready && !tool(id).busy).map(([, n]) => n);
  if (tool("clamav")?.ready && tool("clamav").data_missing) out.push("базы ClamAV");
  if (tool("yara")?.data_missing) out.push("правила YARA");
  return out;
}
function prepCard(){
  const pt = TASK.prepare;
  if (pt?.status === "running") return {lvl: "warn", t: "Готовлю ScanHub к работе…", s: pt.progress || "ставлю сканеры и скачиваю базы",
    b: ["Остановить", `data-task-cancel="prepare"`]};
  const miss = prepMissing();
  if (!miss.length) return null;
  return {lvl: "warn", primary: true, t: "Подготовь ScanHub к работе", b: ["Подготовить", `data-task-run="prepare"`],
    s: `Сейчас проверки неполные — не хватает: ${miss.join(", ")}. Одно нажатие — всё скачается и поставится само с официальных сайтов ` +
       `(около 1 ГБ, 5–15 минут, окно можно свернуть).`};
}

// ============================================================ ГЛАВНАЯ: «Что стоит сделать»
let TODO = [], SELFUPD = null;
document.addEventListener("click", async e => {
  if (!e.target.closest("[data-self-update]")) return;
  const u = SELFUPD || {};
  if (!await modal({title: `Обновить ScanHub до ${u.latest}?`, icon: "↑", ok: "Обновить", cancel: "Позже",
      html: `${u.notes ? `<div class="grp">Что нового</div><div class="sub" style="white-space:pre-wrap;max-height:260px;overflow:auto">${esc(u.notes)}</div>` : ""}
        <p class="sub" style="margin-top:10px">ScanHub скачает архив с GitHub (${esc(u.repo || "")}), сверит контрольную сумму, поставит поверх и перезапустится — окно обновится само. Ключи, история и карантин останутся.${u.url ? ` <a data-link="${esc(u.url)}">Страница выпуска</a>` : ""}</p>`})) return;
  toast("Обновляю ScanHub…", "скачиваю и проверяю архив", "info", 20000);
  try { await api("/api/self_update/apply", {}) } catch (err) { return toast("Обновить не получилось", err.message, "err", 9000) }
  document.body.insertAdjacentHTML("beforeend", `<div class="mdl-back"><div class="mdl"><div class="mdl-top"><span class="mdl-ic">↑</span><h3>ScanHub обновлён — перезапускаюсь…</h3></div><p class="sub">Окно перезагрузится само через несколько секунд.</p></div></div>`);
  const t0 = Date.now();
  const wait = async () => {                       // ждём новый сервер и перезагружаем окно (у нового сервера новый ключ доступа)
    try { const r = await fetch("/api/version"); if (r.ok) return location.reload() } catch {}
    if (Date.now() - t0 < 60000) setTimeout(wait, 1000);
  };
  setTimeout(wait, 2500);
});
setTimeout(() => api("/api/self_update").then(r => { SELFUPD = r; if (r.newer && PAGE === "home") renderTodo() }).catch(() => {}), 4000);
function prepHome(){
  ["restore", "game", "quarantine_list", "diag", "hwcheck", "app_links"].forEach(n => ensureTask(n));
  if (USAGE === undefined) api("/api/usage").then(r => { USAGE = r.on ?? null; if (PAGE === "home") renderTodo() }).catch(() => {});
}
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-usage]");
  if (!b) return;
  USAGE = (await api("/api/usage", {on: b.dataset.usage === "1"}).catch(() => ({on: null}))).on;
  toast(USAGE ? "Спасибо!" : "Хорошо, не буду", USAGE ? "ScanHub будет раз в день отмечаться у автора — без личных данных" : "ничего не отправляется; изменить можно в ⚙ Настройках");
  renderTodo();
});
function computeTodo(){
  const T = [], add = (lvl, t, s, b) => T.push({lvl, t, s, b});
  const prep = prepCard();
  if (prep) T.push(prep);
  if (USAGE === null) T.push({lvl: "info", t: "Помочь автору ScanHub?", s: "Раз в день сообщать автору, что ScanHub запущен: случайный номер этой копии, версия, язык и номер сборки Windows. Без имён, файлов и находок. Так автор узнаёт, сколько людей пользуется ScanHub. Изменить можно в ⚙ Настройках.",
    b: ["Разрешить", `data-usage="1"`], b2: ["Не надо", `data-usage="0"`]});
  if (TASK.app_links?.result && !TASK.app_links.result.ok && store.get("links.ack") !== "1")
    add("info", "Создай ярлык ScanHub", "Ярлык на рабочем столе и в меню «Пуск» — чтобы открывать ScanHub в один клик, не заходя в папку.", ["Создать ярлык", `data-task-run="app_links_create"`]);
  if (SELFUPD?.newer) add("warn", `Вышла новая версия ScanHub — ${SELFUPD.latest}`, SELFUPD.asset
      ? `У тебя ${SELFUPD.current}. «Обновить» скачает её с GitHub, сверит контрольную сумму и поставит поверх — ключи, история и карантин останутся. Что нового — по ссылке «Что нового».`
      : `У тебя ${SELFUPD.current}. Скачай архив новой версии со страницы выпуска и распакуй поверх папки ScanHub (папку data не трогай — там твои ключи и история).`,
    SELFUPD.asset ? ["Обновить", `data-self-update="1"`] : ["Открыть страницу", `data-link="${esc(SELFUPD.url || "")}"`]);
  const d = tool("defender")?.system;
  if (d && d.realtime === false) add("bad", "Защита Windows выключена", "Защита в реальном времени Microsoft Defender отключена — включи её.", ["Открыть", `data-launch="defender"`]);
  const c = (M?.now?.disks || []).find(x => x.mount === "C:");
  if (c && c.percent >= 85) add(c.percent >= 92 ? "bad" : "warn", `На диске C: свободно всего ${fmtB(c.total - c.used)} (${100 - Math.round(c.percent)}%)`,
    "Когда место кончается, Windows тормозит и не может поставить обновления. Начни с мусора и Корзины, потом посмотри, что занимает место.", ["Освободить место", `data-go-page="clean:junk"`]);
  for (const t of TOOLS) {
    const s = t.state || {};
    if (t.busy) continue;
    if (prep && ["clamav", "yara"].includes(t.id) && t.data_missing) continue;      // это и так сделает «Подготовить»
    if (t.ready && t.data_missing && t.needs_data) add("warn", `${t.name}: ${t.needs_data.label.toLowerCase()}`, "Пока этого нет, сканер не участвует в проверках.",
      ["Скачать", `data-run="${t.id}" data-mode="${esc(t.needs_data.mode)}"`]);
    else if (s.error) add("warn", `${t.name}: не получилось`, s.error, ["Подробнее", `data-go-page="tools"`]);
    else if (t.stale && t.ready && t.id === "yara") add("info", "Правила YARA устарели", `Им ${t.age_days} дн. Свежие правила ловят новые вирусы.`, ["Обновить", `data-run="yara" data-mode="update"`]);
  }
  // застрявшее обновление BIOS или другой прошивки (из проверки комплектующих) — человек видит его при каждой загрузке
  const hw = TASK.hwcheck?.result, hwItems = Array.isArray(hw) ? hw : hw?.items || [];
  for (const i of hwItems.filter(i => i.comp === "BIOS" && /не устанавливается/.test(i.title || "")))
    add(i.lvl === "info" ? "info" : "warn", i.title, i.text + " " + (i.how || ""), ["Подробнее", `data-go-page="health:hw"`]);
  const deep = HISTORY.find(h => h.tool === "deep");
  if (deep?.verdict?.[0] === "threat") add("bad", "Глубокая проверка нашла угрозы", deep.verdict[1], ["Посмотреть", `data-go-page="scan:deep"`]);
  else if (!deep || (Date.now() - new Date(deep.started)) / 864e5 > 14) add("info", deep ? `Глубокая проверка была ${ago(deep.started)}` : "Глубокую проверку ещё не запускали",
    "Все сканеры по очереди: процессы, майнеры, сеть, автозагрузка, файлы. 15–40 минут, можно свернуть окно.", ["Начать", `data-go-page="scan:deep"`]);
  const q = (TASK.quarantine_list?.result?.items || []).length;
  if (q) add("info", `В карантине файлов: ${q}`, "Они обезврежены и не запустятся. Если файл нужен и ты уверен в нём — его можно вернуть.", ["Открыть", `data-go-page="scan:quar"`]);
  if (TASK.game?.result?.active) add("warn", "Включён игровой режим", "После игры выключи его — вернутся режим питания и приостановленные службы.", ["Выключить", `data-task-run="game_off"`]);
  const rs = TASK.restore?.result;
  if (rs && !rs.enabled) add("info", "Точки восстановления выключены", "Если обновление или драйвер что-то сломает, откатить Windows будет нельзя. Свои изменения ScanHub и так умеет отменять.",
    ["Подробнее", `data-go-page="privacy:restore"`]);
  if (TASK.health?.result?.reboot_pending) add("warn", "Нужна перезагрузка", "Обновления Windows ждут перезагрузки, чтобы установиться.");
  const dg = TASK.diag?.result;
  if (dg) {
    const week = iso => iso && (Date.now() - new Date(iso)) / 864e5 <= 7;
    const bs = dg.bsod.filter(b => week(b.t)), wh = dg.whea.filter(w => week(w.t) && w.lvl <= 2), dk = dg.disk.filter(d => week(d.t) && d.lvl <= 2);
    if (bs.length) add("bad", `За неделю синих экранов: ${bs.length}`, `Последний — ${bs[0].name}: ${bs[0].desc}.`, ["Почему", `data-go-page="health:crash"`]);
    if (wh.length) add("bad", "Были аппаратные ошибки", "Процессор, память или шина сообщили о неисправимой ошибке.", ["Подробнее", `data-go-page="health:crash"`]);
    if (dk.length) add("bad", "Были ошибки диска", "Сделай резервную копию важных файлов и проверь диск.", ["Подробнее", `data-go-page="health:crash"`]);
    const cr = dg.crashes.filter(c => week(c.last)).sort((a, b) => b.count - a.count)[0];
    if (cr) add("info", `${cr.app} вылетала за неделю${cr.count > 1 ? ` (${cr.count} раза)` : ""}`, `Вероятная причина: ${cr.what}.`, ["Почему", `data-go-page="health:crash"`]);
    const miss = (dg.runtimes || []).filter(x => !x.ok && x.need);
    if (miss.length) add("warn", `Не хватает компонентов: ${miss.map(x => x.name).join(", ")}`, "Из-за этого программы и игры могут не запускаться.", ["Установить", `data-go-page="health:runtimes"`]);
  }
  const ord = {bad: 0, warn: 1, info: 2};
  return T.sort((a, b) => ord[a.lvl] - ord[b.lvl]);
}
let TODO_HTML = "";
// советы («i») на главной можно убрать кнопкой «Понятно»; текст пункта с числом — если число изменится, пункт вернётся
const todoAck = () => { try { return new Set(JSON.parse(store.get("todo.ack") || "[]")) } catch { return new Set() } };
function renderTodo(){
  const ack = todoAck();
  const all = computeTodo(), hidden = all.filter(x => x.lvl === "info" && ack.has(x.t));
  TODO = all.filter(x => !hidden.includes(x));
  const ic = {bad: ["threat", "!"], warn: ["suspicious", "!"], info: ["running", "i"]};
  const html = TODO.length ? `<h2 class="sec">Что стоит сделать</h2><div class="checks">${TODO.map(x => `<div class="check">
      <span class="ic ic-${ic[x.lvl][0]}">${ic[x.lvl][1]}</span><span><b>${esc(x.t)}</b><span class="sub">${esc(x.s)}</span></span>
      <span class="acts">${x.primary ? "" : aiBtn(x.t, x.s, {source: "Главная · Что стоит сделать"})}${x.b ? `<button class="small${x.lvl === "bad" || x.primary ? " primary" : ""}" ${x.b[1]}>${esc(x.b[0])}</button>` : ""}${x.b2 ? ` <button class="small" ${x.b2[1]}>${esc(x.b2[0])}</button>` : x.lvl === "info" ? ` <button class="small" data-todo-ack="${esc(x.t)}" title="Убрать из списка">Понятно</button>` : ""}</span></div>`).join("")}</div>
      ${hidden.length ? `<div class="sub" style="margin-top:6px">Скрыто советов: ${hidden.length}. <a data-todo-unack>Показать снова</a></div>` : ""}`
    : `<h2 class="sec">Что стоит сделать</h2><div class="note info">Сейчас ничего срочного. 👍${hidden.length ? ` <a data-todo-unack>Показать скрытые советы (${hidden.length})</a>` : ""}</div>`;
  if (html === TODO_HTML) return;                // не перерисовывать без изменений (данные приходят каждые 1,5 с)
  TODO_HTML = html;
  $("#todo").innerHTML = html;
  renderNav();
}
// сканеры, которые не смогли участвовать в «Проверить файл/папку», — чтобы пользователь видел, что проверка неполная
function excludedOf(tools){
  // дополнительные онлайн-сервисы (optional) без ключа — не «неполная проверка», а просто не подключены
  return TOOLS.filter(t => t.modes.some(m => m.multi) && !tools.includes(t) && (!t.ready || t.data_missing) && !(t.optional && isService(t) && !t.ready)).map(t => ({
    name: t.name,
    reason: (t.data_missing ? (t.needs_data?.label || "нет баз") : isService(t) ? "нет API-ключа" : status(t)[1]) + " — в проверке не участвовал",
    fix: t.data_missing && t.needs_data ? {run: [t.id, t.needs_data.mode]} : isService(t) ? {settings: true} : t.missing ? null : {install: t.id}}));
}

// ============================================================ ПРОВЕРКА: результат простого режима
function problemsHtml(list, title = "Не сработало проверок"){
  if (!list?.length) return "";
  return `<div class="note bad problems"><b>⚠ ${title}: ${list.length}.</b> Результат неполный — исправь и проверь ещё раз.
    <div class="checks" style="margin-top:8px">${list.map(p => `<div class="check"><span class="ic ic-threat">!</span>
      <span><b>${esc(p.step)}</b><span class="sub">${esc(p.text)}</span></span><span>${fixBtn(p.fix)}</span></div>`).join("")}</div></div>`;
}
function fixBtn(f){
  if (!f) return "";
  if (f.install) return `<button class="small primary" data-install="${esc(f.install)}">Установить</button>`;
  if (f.run) return `<button class="small primary" data-run="${esc(f.run[0])}" data-mode="${esc(f.run[1])}">${f.run[1] === "update" ? "Скачать базы" : "Запустить"}</button>`;
  if (f.settings) return `<button class="small" data-settings>⚙ Настройки</button>`;
  if (f.open) return `<button class="small" data-launch="${esc(f.open)}">Открыть</button>`;
  if (f.rerun) return `<button class="small" id="deepStart">Проверить ещё раз</button>`;
  if (f.page) return `<button class="small" data-go-page="${esc(f.page)}">Открыть</button>`;
  return "";
}
function qButtons(files){
  files = (files || []).filter(f => f.path);
  if (!files.length) return "";
  return `<div class="qbox"><div class="sub">Найденные файлы можно убрать в карантин: они перестанут запускаться, а при ошибке их можно вернуть.</div>
    ${files.map(f => `<div class="qf"><span><b>${esc(f.path.split("\\").pop())}</b><span class="sub mono">${esc(f.path)}</span>${f.name ? `<span class="sub">${esc(f.name)}</span>` : ""}</span>
      <span class="acts"><a data-open="${esc(f.path)}">папка</a> <button class="small" data-file-why="${esc(f.path)}">Почему?</button> <button class="small danger" data-quar="${attr([f])}">В карантин</button></span></div>`).join("")}
    ${files.length > 1 ? `<button class="small danger" data-quar="${attr(files)}">Все в карантин (${files.length})</button>` : ""}</div>`;
}
// ============================================================ ПРОВЕРКА: общий итог «можно запускать или нет»
// Сканеры часто спорят: один насторожился, остальные нет. Решение складываем из весов:
// сильные сигналы (Defender/ClamAV нашли, 3+ антивируса на VirusTotal не по эвристике, подпись повреждена) — «не запускай»;
// средние (несколько срабатываний, ИИ-сканеры уверенно) — «лучше не запускать», если файл не подписан известным издателем;
// слабые (одна эвристика/ИИ на VirusTotal, «подозрительно» у Filescan/Atomdrift) — почти всегда ложные тревоги.
const ML_NAME = /(^|[^a-z])(ml|ai|gen|heur\w*|generic|suspicious|susp|score|confidence|behav\w*|reputation|unsafe|riskware|pua|pup|not-a-virus|artemis|cloud|static|deep\w*|malware-gen|kcloud|lowfi|malicious\.(high|moderate|low))([^a-z]|$)|!ml|\.ml\b|machinelearning|wacatac\.\w!ml/i;
const lc = s => String(s || "").toLowerCase();
function atomFindings(text){
  const out = [], lines = String(text || "").split("\n");
  lines.forEach((l, i) => {
    const m = l.match(/^\s*(HOSTILE|SUSPECT)\[(\d+)%\]\s+(.+?)\s+·\s+(.*)$/);
    if (m) out.push({kind: m[1], pct: +m[2], path: m[3], what: m[4], notes: lines.slice(i + 1, i + 6).filter(x => /^\s+(“|●|[A-Za-zА-Яа-я])/.test(x) && !/^\s*[0-9a-f]{64}\s*$/.test(x) && !/^\s*[⠀-⣿]/.test(x)).map(x => x.replace(/[\u3000-\u9fff\u4e00-\uffff]+/g, "").trim()).filter(Boolean).slice(0, 3)});
  });
  return out;
}
function adviceOf(rows, b){
  const done = rows.filter(r => r.status !== "running");
  const by = id => done.find(r => r.tool === id);
  const sigs = by("signature")?.details || [];
  const folder = b.kind === "folder" || sigs.length > 1 || /\\$/.test(b.target || "");
  const signer = f => { const s = sigs.find(x => lc(x.file) === lc(f)) || (!folder && sigs.length === 1 ? sigs[0] : null); return s?.status === "Valid" ? s.signer : null };
  const name = f => String(f || "").split("\\").pop();
  const strong = [], medium = [], weak = [];
  const def = by("defender"), clam = by("clamav"), vt = by("virustotal"), fs = by("filescan"), atom = by("atomscan"), yara = by("yara"), md = by("metadefender"), ha = by("hybrid"), circl = by("circl");
  if (def?.verdict?.[0] === "threat") strong.push("Microsoft Defender нашёл угрозу");
  if (clam?.verdict?.[0] === "threat") strong.push("ClamAV нашёл угрозу, и перепроверка её подтвердила");
  for (const s of sigs.filter(s => s.status === "HashMismatch")) strong.push(`${s.name}: цифровая подпись повреждена — файл изменили после того, как его подписал издатель`);
  for (const [r, site] of [[vt, "VirusTotal"], [md, "MetaDefender"]]) for (const d of r?.details || []) {
    const hits = (d.engines || []).filter(e => e.c === "malicious" || e.c === "suspicious");
    if (!hits.length) continue;
    const mal = d.positives || 0, heur = hits.every(e => ML_NAME.test(e.r)), sg = signer(d.file);
    const who = hits.slice(0, 3).map(e => e.e).join(", ") + (hits.length > 3 ? "…" : "");
    const txt = `${d.name}: на ${site} тревогу подняли ${hits.length} из ${d.total} антивирусов (${who})`;
    if (mal >= 6 || (mal >= 3 && !heur && !sg)) strong.push(txt);
    else if (sg && mal <= 4) weak.push(`${txt} — файл подписан «${sg}», похоже на ложную тревогу`);
    else if (heur && hits.length <= 2) weak.push(`${txt} — сработала только эвристика или ИИ, обычно это ложная тревога`);
    else medium.push(txt);
  }
  // подробностей нет (итог восстановлен из истории после перезапуска) — учитываем хотя бы сам вердикт
  for (const r of [vt, fs, md, ha]) if (r && !(r.details || []).length && ["threat", "suspicious"].includes(r.verdict?.[0]))
    (r.verdict[0] === "threat" ? medium : weak).push(`${r.tool_name}: ${lc(r.verdict[1])} — подробности недоступны, проверь файл ещё раз`);
  for (const d of fs?.details || []) {
    if (d.verdict === "threat") (signer(d.file) ? weak : medium).push(`${d.name}: Filescan считает опасным` + (signer(d.file) ? ` — но файл подписан «${signer(d.file)}»` : ""));
    else if (d.verdict === "suspicious") weak.push(`${d.name}: Filescan насторожился — у него много ложных тревог на библиотеках и установщиках`);
  }
  for (const d of ha?.details || []) {
    const fam = d.family ? `, семейство ${d.family}` : "", sc = d.score != null ? ` (оценка ${d.score}/100${fam})` : fam;
    if (d.verdict === "threat") (signer(d.file) ? weak : medium).push(`${d.name}: в песочнице Hybrid Analysis файл вёл себя как вредонос${sc}` + (signer(d.file) ? ` — но файл подписан «${signer(d.file)}»` : ""));
    else if (d.verdict === "suspicious") weak.push(`${d.name}: песочница Hybrid Analysis насторожилась${sc} — у установщиков и системных утилит так бывает часто`);
  }
  if (atom && ["threat", "suspicious"].includes(atom.verdict?.[0])) {
    const f = atomFindings(atom.text);
    for (const x of f.length ? f : [{kind: atom.verdict[0] === "threat" ? "HOSTILE" : "SUSPECT", path: b.target, pct: null}]) {
      const sg = signer(x.path), txt = `${name(x.path)}: ИИ-сканер Atomdrift ${x.kind === "HOSTILE" ? "считает вредоносным" : "насторожился"}${x.pct ? ` (уверенность ${x.pct}%)` : ""}`;
      (x.kind === "HOSTILE" && !sg ? medium : weak).push(sg ? `${txt} — файл подписан «${sg}»` : txt);
    }
  }
  if (yara?.verdict?.[0] === "threat") (yara.found || []).forEach(f => (signer(f.path) ? weak : medium).push(`${name(f.path)}: правила YARA — ${f.name || "совпадение с признаками вредоноса"}`));
  // файл есть в базе известных дистрибутивов (NIST NSRL) — сигналы эвристик почти наверняка ложные
  const known = (circl?.details || []).filter(d => d.known && !d.malicious);
  for (const d of circl?.details || []) if (d.malicious) strong.push(`${d.name}: в базе известных файлов CIRCL отмечен как вредоносный`);
  if (known.length && !strong.length && medium.length) { weak.push(...medium.map(x => x + " — но это известный оригинальный файл из дистрибутива (база NIST NSRL)")); medium.length = 0 }
  // насколько полной была проверка
  const okRows = done.filter(r => ["clean", "unknown", "threat", "suspicious"].includes(r.verdict?.[0]));
  const engines = ["defender", "clamav", "virustotal"].filter(id => ["clean", "unknown", "threat", "suspicious"].includes(by(id)?.verdict?.[0]));
  const notes = [];
  if (!folder && sigs[0]?.status === "Valid") notes.push(`Подписан издателем «${sigs[0].signer}», подпись цела — файл не меняли после выпуска.`);
  else if (!folder && sigs[0] && sigs[0].status === "NotSigned") notes.push("Подписи нет — это обычно для небольших программ и игр, но такие файлы стоит скачивать только с официального сайта.");
  if (!folder && known.length) notes.push(`Файл есть в базе известных файлов CIRCL/NIST NSRL: это оригинальный файл из дистрибутива ${known[0].product || "программы"}, его не подменяли.`);
  if (vt && (vt.details || []).some(d => d.missing)) notes.push("VirusTotal этот файл ещё не видел — это бывает с редкими и свежими файлами.");
  if (engines.length < 2) notes.push("Проверка неполная: сработало мало основных антивирусов — исправь ошибки ниже и проверь ещё раз.");
  const W = folder ? {ok: "Можно пользоваться", warn: "Лучше не запускать программы из этой папки", bad: "В папке опасные файлы — не запускай их"}
                   : {ok: "Можно запускать", warn: "Лучше не запускать", bad: "Не запускай этот файл"};
  if (!okRows.length) return {cls: "i-warn", icon: "!", title: "Не удалось проверить", text: "Ни один сканер не смог выполнить проверку — смотри причины ниже.", why: [], notes: []};
  if (strong.length) return {cls: "i-bad", icon: "✕", title: W.bad, text: "Убери найденное в карантин или удали. Если это нужная программа — скачай её заново с официального сайта.", why: strong.concat(medium), notes};
  if (medium.length) return {cls: "i-warn", icon: "!", title: W.warn, text: "Сигналы есть, но не однозначные. Запускай, только если точно знаешь, откуда файл, и скачал его с официального сайта.", why: medium.concat(weak), notes};
  if (weak.length) return {cls: "i-ok", icon: "✓", title: W.ok, text: "Настоящих угроз не найдено. Отдельные тревоги похожи на ложные:", why: weak, notes};
  return {cls: "i-ok", icon: "✓", title: W.ok, text: `Ни один из ${okRows.length} сканеров не нашёл ничего опасного.`, why: [], notes};
}

// ---------- подробности по одному сканеру (нажатие на строку)
const VT_CAT = {"type-unsupported": "не поддерживает такой тип файла", timeout: "не успел", "confirmed-timeout": "не успел", failure: "ошибка"};
const HA_RAW = {malicious: "вредонос", suspicious: "подозрительно", "no specific threat": "угроз не видно", whitelisted: "в белом списке", "no verdict": "без вердикта"};
const FS_RAW = {no_threat: "угроз нет", benign: "безопасен", informational: "безопасен", suspicious: "подозрительно", likely_malicious: "скорее всего опасен", malicious: "опасен", unknown: "нет в базе"};
const cleanLog = t => String(t || "").split("\n").filter(l => !/^\s*[⠀-⣿]/.test(l) && !l.includes("━") && !/^\s*\[(\d+)\/\1\]\s*$/.test(l))
  .map(l => l.replace(/[\u3000-\u9fff\u4e00-\uffff]{3,}/g, "")).join("\n").replace(/\n{3,}/g, "\n\n").trim();
const extA = (href, label) => href ? `<a class="ext" href="${esc(href)}" target="_blank" rel="noopener">${esc(label)} ↗</a>` : "";
function vtBlock(d, site = "VirusTotal"){
  if (d.missing) return `<div class="det-file"><div class="det-h"><b>${esc(d.name)}</b><span class="pill">нет в базе</span></div>
    <div class="sub">Этот файл на ${site} ещё никто не проверял. Отправлен только отпечаток (хэш), сам файл остался у тебя.</div></div>`;
  const E = d.engines || [], hits = E.filter(e => ["malicious", "suspicious"].includes(e.c));
  const clean = E.filter(e => ["undetected", "harmless"].includes(e.c)), skip = E.filter(e => !["malicious", "suspicious", "undetected", "harmless"].includes(e.c));
  const meta = [d.type, d.size ? fmtSize(d.size) : "", d.first ? "впервые загружен " + new Date(d.first * 1000).toLocaleDateString(LOC) : "",
    d.signer ? "подпись: " + d.signer : "", d.label ? "метка угрозы: " + d.label : ""].filter(Boolean);
  return `<div class="det-file">
    <div class="det-h"><b>${esc(d.name)}</b><span class="pill ${hits.length ? (d.verdict === "threat" ? "bad" : "warn") : "ok"}">${hits.length} из ${d.total}</span></div>
    ${meta.length ? `<div class="sub">${esc(meta.join(" · "))}</div>` : ""}
    ${hits.length ? `<table class="eng"><tr><th>Антивирус</th><th>Что нашёл</th><th></th></tr>${hits.map(e => `<tr><td>${esc(e.e)}</td>
        <td class="${e.c === "malicious" ? "bad" : "warn"}">${esc(e.r || (e.c === "malicious" ? "вредонос" : "подозрительно"))}</td>
        <td class="sub">${ML_NAME.test(e.r) ? "эвристика / ИИ — часто ошибается" : e.c === "suspicious" ? "только подозрение" : ""}</td></tr>`).join("")}</table>`
      : `<div class="okline">✓ Ни один антивирус не считает файл опасным</div>`}
    <details${hits.length ? "" : " open"}><summary>Не нашли ничего: ${clean.length}</summary><div class="chips">${clean.map(e => `<span>${esc(e.e)}</span>`).join("")}</div></details>
    ${skip.length ? `<details><summary>Не проверяли: ${skip.length}</summary><div class="chips">${skip.map(e => `<span>${esc(e.e)} · ${esc(VT_CAT[e.c] || e.c)}</span>`).join("")}</div></details>` : ""}
    ${extA(d.link, "Полный отчёт на " + site)}</div>`;
}
function detailsHtml(r){
  const D = r.details || [];
  if (r.tool === "virustotal" && D.length)
    return `<p class="det-lead">VirusTotal сверяет отпечаток файла с базами ~70 антивирусов. Одно-два срабатывания эвристики почти всегда ложные; опасно, когда файл узнают многие.</p>` + D.map(vtBlock).join("");
  if (r.tool === "metadefender" && D.length)
    return `<p class="det-lead">MetaDefender сверяет отпечаток файла с базами 20+ антивирусных движков OPSWAT. Как и на VirusTotal, одно срабатывание — обычно ложная тревога.</p>` + D.map(d => vtBlock(d, "MetaDefender")).join("");
  if (r.tool === "circl" && D.length)
    return `<p class="det-lead">CIRCL hashlookup — база известных файлов (NIST NSRL: файлы из дистрибутивов программ, сборки Windows и Linux). Он не ищет вирусы, а подтверждает, что файл оригинальный.</p>` +
      D.map(d => `<div class="det-file"><div class="det-h"><b>${esc(d.name)}</b><span class="pill ${d.malicious ? "bad" : d.known ? "ok" : ""}">${d.malicious ? "вредоносный" : d.known ? "известный файл" : "нет в базе"}</span></div>
        ${d.known ? `<div class="sub">${esc([d.product, d.source ? "база " + d.source : "", d.trust != null ? `доверие ${d.trust}/100` : ""].filter(Boolean).join(" · "))}</div>` : `<div class="sub">Это нормально для новых версий, игр и небольших программ.</div>`}
        ${extA(d.link, "Запись в CIRCL")}</div>`).join("");
  if (r.tool === "hybrid" && D.length)
    return `<p class="det-lead">Hybrid Analysis показывает, что делал файл, когда его запускали в песочнице CrowdStrike. Оценка угрозы — от 0 до 100.</p>` +
      D.map(d => `<div class="det-file"><div class="det-h"><b>${esc(d.name)}</b><span class="pill ${{threat: "bad", suspicious: "warn", clean: "ok"}[d.verdict] || ""}">${esc(HA_RAW[d.raw] || d.raw || (d.missing ? "нет в базе" : d.verdict))}</span></div>
        ${d.missing ? `<div class="sub">Этот файл в песочнице ещё никто не запускал. Отправлен только отпечаток (хэш).</div>` : ""}
        ${[d.score != null ? `оценка угрозы ${d.score}/100` : "", d.family ? `семейство: ${d.family}` : "", d.multiscan ? `антивирусы: ${d.multiscan}%` : ""].filter(Boolean).map(x => `<div class="sub">${esc(x)}</div>`).join("")}
        ${extA(d.link, "Отчёт на Hybrid Analysis")}</div>`).join("");
  if (r.tool === "filescan" && D.length)
    return `<p class="det-lead">Filescan.io разбирает файл в песочнице и по репутации. На установщиках и старых библиотеках он часто осторожничает.</p>` +
      D.map(d => `<div class="det-file"><div class="det-h"><b>${esc(d.name)}</b><span class="pill ${{threat: "bad", suspicious: "warn", clean: "ok"}[d.verdict] || ""}">${esc(FS_RAW[d.raw] || d.raw || (d.missing ? "нет в базе" : d.verdict))}</span></div>
        ${d.reports ? `<div class="sub">отчётов о файле: ${d.reports}</div>` : ""}${extA(d.link, "Отчёт на Filescan")}</div>`).join("");
  if (r.tool === "signature" && D.length)
    return `<p class="det-lead">Цифровая подпись показывает, кто выпустил файл и что его не меняли после этого. Подделать действующую подпись вирус не может.</p>
      <table class="eng">${D.map(d => `<tr><td>${esc(d.name)}</td><td class="${d.status === "Valid" ? "ok" : d.status === "HashMismatch" ? "bad" : "sub"}">${d.status === "Valid" ? "✓ " + esc(d.signer) : d.status === "HashMismatch" ? "✕ подпись повреждена" : d.status === "NotSigned" ? "без подписи" : esc(d.status)}</td></tr>`).join("")}</table>`;
  if (r.tool === "atomscan") {
    const f = atomFindings(r.text);
    return `<p class="det-lead">Atomdrift — ИИ-сканер: ищет новые вирусы по устройству файла, без баз. Процент — уверенность модели; у установщиков и упакованных программ он часто ошибается.</p>` +
      (f.length ? f.map(x => `<div class="det-file"><div class="det-h"><b>${esc(x.path.split("\\").pop())}</b><span class="pill ${x.kind === "HOSTILE" ? "bad" : "warn"}">${x.kind === "HOSTILE" ? "вредонос" : "подозрение"} · ${x.pct}%</span></div>
        <div class="sub mono">${esc(x.path)}</div><div class="sub">${esc(x.what)}</div>${x.notes.map(n => `<div class="sub">• ${esc(n)}</div>`).join("")}</div>`).join("") : "");
  }
  return "";
}
function showDetails(id){
  const r = openJobs.find(j => j.id === id);
  if (!r) return;
  const html = detailsHtml(r), log = cleanLog(r.text);
  modal({title: r.tool_name, icon: "i", ok: "Закрыть", cancel: null, wide: true,
    body: r.status === "running" ? "Проверка ещё идёт — ниже то, что уже сделано." : `Итог: ${r.verdict?.[1] || "—"}`,
    html: html + (log ? `<details class="log"${html ? "" : " open"}><summary>Журнал проверки</summary><pre>${esc(log)}</pre></details>` : "")});
}

// файл никто в мире ещё не проверял (свой билд, свежая версия) — онлайн-сервисы по хэшу отвечают «нет в базе».
// Предлагаем загрузить сам файл: VirusTotal прогонит его через ~70 антивирусов, Filescan — в приватной песочнице.
function uploadOffer(rows){
  const vt = rows.find(r => r.tool === "virustotal" && r.status !== "running");
  const d = vt?.details || [];
  if (d.length !== 1 || !d[0].missing || !d[0].file) return "";        // одна проверка по хэшу и файла нет в базе
  const fs = tool("filescan")?.ready;
  return `<div class="note info upload-offer"><b>Этот файл ещё никто не проверял</b> — поэтому онлайн-сервисы ответили «нет в базе»: они ищут файл по отпечатку, сам файл ScanHub без спроса не отправляет.
    Чтобы VirusTotal реально прогнал его через ~70 антивирусов, загрузи файл (до 32 МБ, обычно 1–3 минуты).
    <div class="row-tools" style="margin-top:8px"><button class="small primary" data-upload="virustotal" data-file="${esc(d[0].file)}">Загрузить в VirusTotal</button>
    ${fs ? `<button class="small" data-upload="filescan" data-file="${esc(d[0].file)}">Загрузить в Filescan (приватно)</button>` : ""}</div></div>`;
}

function renderSimpleResult(){
  const box = $("#sResult");
  if (!simpleBatch || !batches[simpleBatch]) { box.hidden = true; return }
  const b = batches[simpleBatch];
  const rows = b.jobs.map(id => openJobs.find(j => j.id === id)).filter(Boolean);
  const running = rows.filter(r => r.status === "running").length;
  let icon, cls, title, text;
  const w = verdictOf(rows);
  const okRows = rows.filter(r => ["clean", "unknown"].includes(r.verdict?.[0]));
  if (running) { cls = "i-run"; icon = '<div class="spin"></div>'; title = b.quick ? "Идёт проверка…" : `Проверяю… ${rows.length - running} из ${rows.length}`;
                 text = b.quick ? "Обычно занимает 2–5 минут. Можно свернуть окно." : "Несколько антивирусов смотрят на файл одновременно." }
  else if (w === "threat") { cls = "i-bad"; icon = "!"; title = "Найдена угроза"; text = "Не открывай и не запускай это. Убери файл в карантин или удали. Если это важная программа — скачай её заново с официального сайта." }
  else if (w === "suspicious") { cls = "i-warn"; icon = "?"; title = "Есть подозрения"; text = "Один из сканеров насторожился. Если не уверен, откуда этот файл, — не запускай его. Подробности — в режиме «Разработчик»." }
  else if (w === "error" && !okRows.length) { cls = "i-warn"; icon = "!"; title = "Не удалось проверить"; text = "Ни один сканер не смог выполнить проверку — смотри причины ниже." }
  else { cls = "i-ok"; icon = "✓"; title = "Угроз не найдено"; text = b.quick ? "Проверка ничего опасного не нашла." : `Ни один из ${okRows.length} сканеров не нашёл ничего опасного.` }
  const adv = running || b.quick ? null : adviceOf(rows, b);
  if (adv) ({cls, icon, title, text} = adv);
  const el = r => { const s = Math.max(0, Math.round((Date.now() - new Date(r.started)) / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}` };
  const vtSum = r => { const d = (r.details || []).filter(x => !x.missing); if (!d.length) return null;
    const hits = d.reduce((n, x) => n + (x.engines || []).filter(e => e.c === "malicious" || e.c === "suspicious").length, 0);
    return d.length === 1 ? (hits ? `тревогу подняли ${hits} из ${d[0].total}` : `чисто у всех ${d[0].total}`) : (hits ? `тревоги в ${d.filter(x => x.positives || x.suspicious).length} из ${d.length} файлов` : `чисто, файлов: ${d.length}`) };
  const plain = r => r.status === "running" ? `проверяет… ${r.started ? el(r) : ""}${r.progress ? " · " + progOf(r.progress).t : ""}${progOf(r.progress).f != null ? ` · ${Math.round(progOf(r.progress).f * 100)}%${etaText(r.started, progOf(r.progress).f) ? ", " + etaText(r.started, progOf(r.progress).f) : ""}` : ""}` :
    (r.tool === "virustotal" || r.tool === "metadefender") && vtSum(r) ? vtSum(r) :
    // CIRCL не ищет вирусы — он только подтверждает, что файл оригинальный из известного дистрибутива
    r.tool === "circl" ? ((r.details || []).some(d => d.malicious) ? "в базе известных файлов отмечен как вредоносный" :
      (r.details || []).some(d => d.known) ? ((r.details || []).length > 1 ? `известных оригинальных файлов: ${r.details.filter(d => d.known).length} из ${r.details.length}` : "известный оригинальный файл, не подменён")
      : r.verdict?.[0] === "error" ? "не смог проверить" : "нет в базе известных файлов — это нормально для новых версий и небольших программ") :
    r.tool === "signature" && r.verdict?.[0] === "clean" ? r.verdict[1] :
    r.verdict?.[0] === "unknown" && tool(r.tool) && !isService(tool(r.tool)) ? (r.verdict[1] || "").toLowerCase() + (r.tool === "signature" ? " — у небольших программ это нормально" : "") : ({clean: "всё чисто", threat: "нашёл угрозу", suspicious: "подозревает", unknown: "файла нет в базе — это нормально для редких файлов",
    error: "не смог проверить", launched: "открыт"}[r.verdict?.[0]] || r.verdict?.[1]);
  const probs = running ? [] : rows.filter(r => r.verdict?.[0] === "error").map(r => ({step: r.tool_name, text: `не смог проверить: ${r.verdict?.[1] || "ошибка"}` + (r.code != null ? ` (код ${r.code})` : ""),
    fix: tool(r.tool)?.needs_data ? {run: [r.tool, tool(r.tool).needs_data.mode]} : null}))
    .concat((b.excluded || []).map(t => ({step: t.name, text: t.reason, fix: t.fix})));
  const found = running ? [] : rows.flatMap(r => r.found || []);
  box.hidden = false;
  box.innerHTML = `<div class="result">
    <div class="big"><div class="icon ${cls}">${icon}</div><div><h3>${title}</h3>${b.target ? `<div class="what">${esc(b.dropped ? b.label + " · проверена копия" : b.target)}</div>` : ""}</div>
      <div style="flex:1"></div>${running ? `<button class="small danger" data-stop-batch="${esc(simpleBatch)}">Остановить</button>` : `${aiBtn(title + (b.target ? " — " + b.target.split("\\").pop() : ""), [text, ...(adv?.why || []), ...(adv?.notes || []), ...rows.map(r => `${r.tool_name}: ${plain(r)}`)].join(" · "), {source: "Проверка файла"})}<button class="small" id="sResClose">Скрыть</button>`}</div>
    <div>${text}</div>
    ${adv?.why?.length ? `<ul class="why">${adv.why.map(w => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
    ${adv?.notes?.length ? `<div class="sub">${adv.notes.map(esc).join(" ")}</div>` : ""}
    ${b.dropped ? `<div class="sub">${esc(b.dropped)}</div>` : ""}
    ${qButtons(found)}
    ${running ? "" : uploadOffer(rows)}
    <div class="sub" style="margin-bottom:-4px">Что сказал каждый сканер — нажми на строку, чтобы увидеть подробности:</div>
    <ul class="scanrows">${rows.map(r => `<li class="det" data-det="${esc(r.id)}" tabindex="0" role="button"><span class="dot ${r.status === "running" ? "run" : (r.verdict?.[0] || "")}"></span><b>${esc(r.tool_name)}</b> — ${esc(plain(r))}<span class="more">Подробнее ›</span></li>`).join("")}</ul>
    ${problemsHtml(probs, "Не участвовали или не сработали")}
    ${!running && prepMissing().length && TASK.prepare?.status !== "running" ? `<div class="row-tools"><button class="small primary" data-task-run="prepare">Подготовить ScanHub — поставить недостающие сканеры</button>
      <span class="sub">около 1 ГБ, один раз</span></div>` : ""}
    ${running ? `<div class="sub">Папки проверяются быстро: только программы, библиотеки, скрипты, архивы и документы с макросами. Дольше всех обычно ClamAV и Atomdrift — они разбирают файлы целиком; VirusTotal на бесплатном ключе проверяет 4 файла в минуту.</div>` : ""}
  </div>`;
}

// ============================================================ общие кусочки панелей
const SEL = {}, SEL_KEY = {};
function sel(name, key, defaults){
  if (SEL_KEY[name] !== key) { SEL[name] = new Set(defaults); SEL_KEY[name] = key }
  return SEL[name];
}
const cb = (name, id, on, extra = "") => `<input type="checkbox" data-sel="${name}" value="${esc(id)}" ${on ? "checked" : ""} ${extra}>`;
const explain = html => `<div class="explain">${html}</div>`;
const adminChip = `<span class="chip-admin" title="Попросит подтверждение администратора (UAC)">🛡 администратор</span>`;
const tgl = (on, attrs, title = "") => `<label class="tgl" title="${esc(title)}"><input type="checkbox" ${on ? "checked" : ""} ${attrs}></label>`;
const pnl = html => `<div class="pnl">${html}</div>`;
const busyErr = (name, text) => taskBusy(name, text) + taskErr(name);
function rpOn(){ return store.get("rp") !== "0" }
function rpBox(){
  const st = TASK.restore?.result;
  const note = !st ? "" : st.enabled ? (st.last ? `последняя: ${esc(st.last.replace("T", " "))}` : "") :
    `<span style="color:var(--warn)">защита системы выключена — точка не будет создана. ScanHub всё равно сохраняет исходные значения и умеет вернуть их сам.</span> <a data-go-page="privacy:restore">подробнее</a>`;
  return `<label class="switch rp"><input type="checkbox" id="rpOn" ${rpOn() ? "checked" : ""}> Создать точку восстановления Windows перед изменением <span class="sub">${note}</span></label>`;
}
const pathShort = p => p.length > 70 ? p.slice(0, 28) + "…" + p.slice(-38) : p;
function pickRow(task, label, extra = ""){
  const drives = (M?.now?.disks || []).map(d => d.mount);
  return `<div class="row-tools">${(drives.length ? drives : ["C:"]).map(d => `<button data-task-run="${task}" data-args="${attr({path: d + "\\", ...JSON.parse(extra || "{}")})}">Диск ${esc(d)}</button>`).join("")}
    <button data-pick-run="${task}" ${extra ? `data-extra="${esc(extra)}"` : ""}>${label}</button></div>`;
}
function sizeBar(v, max, crit){ return `<div class="bar sz"><div class="${crit ? "crit" : ""}" style="width:${max ? Math.max(1, v / max * 100) : 0}%"></div></div>` }

// ============================================================ карантин
function pQuar(dev){
  const t = TASK.quarantine_list, items = t?.result?.items || [];
  return pnl(`${head("Карантин", "Файлы, которые ты убрал в карантин после проверки.")}
    ${explain("Файл переносится в папку ScanHub и кодируется — запустить его больше нельзя, антивирусы его не трогают. Если это была ложная тревога, нажми «Вернуть»: файл вернётся на старое место. «Удалить навсегда» стирает его без возможности вернуть.")}
    ${busyErr("quarantine_list", "Загружаю…")}${taskErr("q_restore")}${taskErr("q_delete")}
    ${items.length ? `<table class="t small">${items.map(i => `<tr><td><b>${esc(i.path.split("\\").pop())}</b><div class="sub">${esc(i.name || "")}${i.engine ? " · " + esc(i.engine) : ""}</div>
        ${dev ? `<div class="sub mono">${esc(i.path)} · SHA-256 ${esc(i.sha256)}</div>` : `<div class="sub">${esc(pathShort(i.path))}</div>`}</td>
        <td class="n">${fmtB(i.size)}</td><td class="n sub">${esc(i.date.replace("T", " "))}</td>
        <td class="acts">${aiBtn(`Файл в карантине: ${i.path.split("\\").pop()}`, `Путь: ${i.path}. Почему в карантине: ${i.name || "?"}. Нашёл: ${i.engine || "?"}. Когда: ${i.date}. Стоит ли его вернуть или удалить?`, {source: "Карантин"})}
          <button class="small" data-task-run="q_restore" data-args="${attr({id: i.id})}" data-confirm="Вернуть файл на место? Делай это, только если уверен, что он безопасен.">Вернуть</button>
          <button class="small danger" data-task-run="q_delete" data-args="${attr({id: i.id})}" data-confirm="Удалить файл навсегда? Вернуть его будет нельзя.">Удалить навсегда</button></td></tr>`).join("")}</table>`
      : t?.result ? `<div class="empty">Карантин пуст</div>` : ""}`);
}

// ============================================================ очистка: мусор
const JUNK_GROUPS = ["Windows", "Браузеры", "Программы", "Игры и видеокарта", "Разработка"];
function pJunk(dev){
  const t = TASK.junk_scan, r = t?.result, run = TASK.junk_clean;
  const btn = `<button data-task-run="junk_scan" ${t?.status === "running" ? "disabled" : ""}>${r ? "Пересчитать" : "Найти мусор"}</button>`;
  if (!r) return pnl(head("Мусор и кэши", "Временные файлы, кэши браузеров, программ и игр, Корзина.", btn) + busyErr("junk_scan", "Считаю, сколько места можно освободить… 5–15 секунд"));
  const S = sel("junk", t.finished, r.categories.filter(c => c.safe && !c.admin && c.size > 0).map(c => c.id));
  const all = [...r.categories, {id: "recycle", grp: "Корзина", label: `Корзина (${r.recycle.count} файлов)`, size: r.recycle.size, safe: false,
    desc: "Файлы, которые ты уже удалил. Очистка удаляет их окончательно — вернуть будет нельзя. Перед очисткой загляни в Корзину, нет ли там нужного."}];
  const total = all.filter(c => S.has(c.id)).reduce((a, c) => a + (c.size || 0), 0);
  const groups = [...JUNK_GROUPS, "Корзина"].filter(g => all.some(c => c.grp === g));
  const res = run?.result;
  return pnl(`${head("Мусор и кэши", `На C: свободно ${fmtB(r.c_free)} из ${fmtB(r.c_total)}`, btn)}
    ${explain("<b>Что такое кэш.</b> Программы сохраняют копии картинок, страниц и скомпилированных данных, чтобы в следующий раз открываться быстрее. Кэш можно удалять: программа создаст его заново, просто первый запуск будет чуть медленнее. Удаляются только файлы старше суток, а занятые программами — пропускаются. Личные файлы, пароли и настройки не трогаются.")}
    ${busyErr("junk_scan", "Пересчитываю…")}${busyErr("junk_clean", "Удаляю… если появится окно UAC — подтверди (для системных папок)")}
    ${res ? `<div class="note ${res.errors?.length ? "warn" : "info"}">Освобождено <b>${fmtB(res.freed)}</b>${res.skipped ? `, пропущено занятых файлов: ${res.skipped} (их держат открытые программы)` : ""}.${res.errors?.length ? "<br>" + res.errors.map(esc).join("<br>") : ""}
      ${res.freed < 1 << 20 ? `<br>Если освободилось мало — значит, в отмеченных папках только свежие файлы (моложе суток) или занятые открытыми программами. ScanHub их специально не трогает; они удалятся при следующей очистке.` : ""}</div>` : ""}
    ${groups.map(g => `<div class="grp">${g}</div><div class="rows">${all.filter(c => c.grp === g).map(c => `<label class="crow">${cb("junk", c.id, S.has(c.id))}
        <span><b>${esc(c.label)}</b> ${c.admin ? adminChip : ""}${c.safe ? "" : ` <span class="chip-note">по желанию</span>`}<span class="sub">${esc(c.desc || "")}</span>
          ${c.fresh > 1 << 20 ? `<span class="sub" style="color:var(--muted)">ещё ${fmtB(c.fresh)} — свежие файлы (моложе ${c.older_days >= 2 ? c.older_days + " дн." : "суток"}): их программы могут использовать прямо сейчас, удалятся при следующей очистке</span>` : ""}
          ${dev ? `<span class="sub mono">${c.paths?.map(esc).join("<br>") || ""}</span>` : ""}</span>
        <span class="n">${c.always && !c.size ? "—" : fmtB(c.size)}</span></label>`).join("")}</div>`).join("")}
    <div class="stickybar"><span>Выбрано: <b>${fmtB(total)}</b></span><div class="grow"></div>
      <button class="primary" data-junk-go ${!S.size || run?.status === "running" ? "disabled" : ""}>Очистить выбранное</button>
      <button data-launch="cleanmgr">Очистка диска Windows</button></div>
    <div class="sub">«Очистка диска Windows» умеет удалять ещё и старые обновления Windows и предыдущую версию системы (кнопка «Очистить системные файлы»).</div>`);
}

// ============================================================ очистка: ярлыки, PATH, драйверы
function pShortcuts(dev){
  const t = TASK.shortcuts, r = t?.result, rm = TASK.shortcuts_remove?.result;
  const btn = `<button data-task-run="shortcuts" ${t?.status === "running" ? "disabled" : ""}>Проверить снова</button>`;
  const S = r ? sel("lnk", t.finished, r.broken.map(b => b.path)) : new Set();
  return pnl(`${head("Битые ярлыки", r ? `проверено ярлыков: ${r.total}, битых: ${r.broken.length}` : "Ярлыки в меню «Пуск», на рабочем столе и в панели задач, которые ведут в никуда", btn)}
    ${explain("Ярлык — это ссылка на программу. Когда программу удаляют или переносят, ярлык остаётся и при запуске выдаёт ошибку. Ярлыки на отключённые флешки и диски не считаются битыми. Перед удалением ScanHub сохраняет копии ярлыков в <code>D:\\ScanHub\\data\\backups\\shortcuts</code>.")}
    ${busyErr("shortcuts", "Проверяю ярлыки…")}${busyErr("shortcuts_remove", "Удаляю…")}
    ${rm ? `<div class="note info">Удалено ярлыков: ${rm.removed}. Копии — в <code>${esc(rm.backup)}</code>.${rm.errors?.length ? "<br>" + rm.errors.map(esc).join("<br>") : ""}</div>` : ""}
    ${r ? (r.broken.length ? `<div class="rows">${r.broken.map(b => `<label class="crow">${cb("lnk", b.path, S.has(b.path))}
        <span><b>${esc(b.name)}</b> <span class="sub-inline">${esc(b.where)}</span> ${b.admin ? adminChip : ""}<span class="sub">ведёт на ${esc(b.target)} — этого файла нет</span>
        ${dev ? `<span class="sub mono">${esc(b.path)}</span>` : ""}</span><span></span></label>`).join("")}</div>
      <div class="row-tools"><button class="primary" data-sel-run="shortcuts_remove" data-sel-name="lnk" data-sel-arg="paths" data-confirm="Удалить отмеченные ярлыки? Копии сохранятся в папке резервных копий ScanHub.">Удалить отмеченные</button></div>`
      : `<div class="note info">Битых ярлыков нет. 👍</div>`) : ""}`);
}
function pEnvPath(dev){
  const t = TASK.envpath, r = t?.result, fx = TASK.envpath_fix?.result;
  const btn = `<button data-task-run="envpath" ${t?.status === "running" ? "disabled" : ""}>Проверить снова</button>`;
  const bad = (r?.entries || []).filter(e => e.problem);
  const S = r ? sel("path", t.finished, bad.filter(e => e.problem !== "диск не подключён").map(e => e.scope + "|" + e.entry)) : new Set();
  const shown = dev ? (r?.entries || []) : bad;
  return pnl(`${head("Переменная PATH", r ? `записей: ${r.entries.length}, лишних: ${bad.length}` : "", btn)}
    ${explain("<b>PATH</b> — список папок, где Windows ищет программы, когда ты пишешь команду в терминале (python, git, node…). После удаления программ в нём остаются записи на несуществующие папки и повторы. Они не опасны, но замедляют запуск команд и могут подсовывать старую версию программы. Старое значение сохраняется в <code>data\\backups</code>.")}
    ${busyErr("envpath", "Читаю PATH…")}${busyErr("envpath_fix", "Сохраняю… для системного PATH появится окно UAC")}
    ${fx ? `<div class="note info">Убрано записей: ${Object.values(fx.removed || {}).reduce((a, b) => a + b, 0)}. Открытые терминалы увидят изменения после перезапуска.</div>` : ""}
    ${r ? (shown.length ? `<div class="rows">${shown.map(e => `<label class="crow">${e.problem ? cb("path", e.scope + "|" + e.entry, S.has(e.scope + "|" + e.entry)) : "<span></span>"}
        <span><b class="mono-b">${esc(e.entry)}</b> <span class="sub-inline">${e.scope === "user" ? "для тебя" : "для всех"}</span> ${e.scope === "system" && e.problem ? adminChip : ""}
        <span class="sub">${e.problem ? (e.problem === "повтор" ? "повторяет запись выше — лишняя" : e.problem === "папки нет" ? "этой папки нет — программа удалена или перенесена" : "диск не подключён — возможно, это флешка, тогда оставь") : "в порядке"}${e.expanded !== e.entry ? " · " + esc(e.expanded) : ""}</span></span><span></span></label>`).join("")}</div>
      ${bad.length ? `${rpBox()}<div class="row-tools"><button class="primary" data-sel-run="envpath_fix" data-sel-name="path" data-sel-arg="remove" data-rp>Убрать отмеченные</button></div>` : ""}`
      : `<div class="note info">В PATH нет лишних записей. 👍</div>`) : ""}`);
}
function pDrvStore(dev){
  const t = TASK.drvstore, r = t?.result, rm = TASK.drvstore_remove?.result;
  const btn = `<button data-task-run="drvstore" ${t?.status === "running" ? "disabled" : ""}>Проверить снова</button>`;
  const S = r ? sel("drv", t.finished, r.old.map(p => p.oem)) : new Set();
  const tot = (r?.old || []).filter(p => S.has(p.oem)).reduce((a, p) => a + (p.size || 0), 0);
  return pnl(`${head("Старые драйверы", r ? `пакетов в хранилище: ${r.packages}, старых неиспользуемых: ${r.old.length} (${fmtB(r.size)})` : "", btn)}
    ${explain("Когда драйвер обновляется, Windows оставляет старую версию в хранилище драйверов — на случай отката. Со временем там копятся сотни мегабайт. Здесь показаны только старые версии, для которых уже установлена новая и которые не использует ни одно устройство. Удаляет сама Windows (pnputil) — используемый драйвер она удалить не даст. Минус: откатить драйвер на эту старую версию потом будет нельзя.")}
    ${busyErr("drvstore", "Читаю хранилище драйверов…")}${busyErr("drvstore_remove", "Удаляю… подтверди окно UAC")}
    ${rm ? `<div class="note ${rm.failed?.length ? "warn" : "info"}">Удалено пакетов: ${rm.removed}.${rm.failed?.length ? "<br>Не удалось:<br>" + rm.failed.map(esc).join("<br>") : ""}${rpNote(rm)}</div>` : ""}
    ${r ? (r.old.length ? `<table class="t small">${r.old.map(p => `<tr><td style="width:1%">${cb("drv", p.oem, S.has(p.oem))}</td>
        <td><b>${esc(p.provider)}</b> · ${esc(p.cls)}<div class="sub">${esc(p.orig)} · версия ${esc(p.version)} → установлена ${esc(p.newest)}</div>${dev ? `<div class="sub mono">${esc(p.oem)} · ${esc(p.folder || "")}</div>` : ""}</td>
        <td class="n">${p.size ? fmtB(p.size) : "—"}</td></tr>`).join("")}</table>
      ${rpBox()}<div class="row-tools"><button class="primary" data-sel-run="drvstore_remove" data-sel-name="drv" data-sel-arg="oems" data-rp data-confirm="Удалить отмеченные старые пакеты драйверов? Windows попросит права администратора.">Удалить отмеченные (${fmtB(tot)})</button></div>`
      : `<div class="note info">Старых пакетов драйверов нет. 👍</div>`) : ""}`);
}
function rpNote(r){
  const p = r?.restore_point;
  if (!p) return "";
  return `<br><span class="sub">${p.status === "ok" ? "✓ Точка восстановления создана" : p.status === "skip" ? "Точка восстановления не создана: Windows разрешает одну в сутки, сегодняшняя уже есть" :
    p.status === "off" ? "Точка восстановления не создана: защита системы выключена" : "Точка восстановления не создана: " + esc(p.text || "")}</span>`;
}

// ============================================================ место на диске
let DISK_VIEW = null;
function pDisk(dev){
  const t = TASK.disk_analyze, r = t?.result;
  const top = `${explain("ScanHub обходит диск или папку и считает размер каждой папки, типы файлов и самые большие файлы. Нажимай на папки, чтобы провалиться внутрь. Удалять можно большие файлы: они уходят в Корзину (место освободится после её очистки).")}
    ${pickRow("disk_analyze", "Выбрать папку…")}${busyErr("disk_analyze", "Считаю… для целого диска это 1–3 минуты")}`;
  if (!r) return pnl(head("Что занимает место", "Выбери диск или папку") + top);
  const v = DISK_VIEW && DISK_VIEW.path.toLowerCase().startsWith(r.root.toLowerCase()) ? DISK_VIEW : r.tree;
  const maxT = Math.max(...r.types.map(x => x.size), 1), maxK = Math.max(...v.items.map(x => x.size), 1);
  const S = sel("big", t.finished, []);
  const u = r.usage;
  const crumbs = [];
  for (let p = v.path; p && p.toLowerCase().startsWith(r.root.toLowerCase()); p = p.includes("\\") && p.replace(/\\[^\\]*$/, "") !== p ? p.replace(/\\[^\\]*$/, "") : null) {
    crumbs.unshift(p);
    if (p.length <= r.root.length) break;
  }
  return pnl(`${head("Что занимает место", `${esc(r.root)} · ${fmtB(r.size)} в ${r.files.toLocaleString(LOC)} файлах · посчитано за ${r.seconds} с${r.denied ? ` · без доступа: ${r.denied} папок` : ""}`)}
    ${top}
    ${u ? `<div><div class="bar big-bar" title="занято ${fmtB(u.used)}"><div class="${u.free / u.total < 0.1 ? "crit" : ""}" style="width:${u.used / u.total * 100}%"></div></div>
      <div class="sub">занято ${fmtB(u.used)} из ${fmtB(u.total)} · свободно <b>${fmtB(u.free)}</b></div></div>` : ""}
    <div class="two">
      <div><div class="grp">Типы файлов</div><div class="typelist">${r.types.sort((a, b) => b.size - a.size).map(x => `<div class="trow"><span>${x.icon} ${esc(x.name)}<span class="sub"> · ${x.count.toLocaleString(LOC)} файлов</span></span>
        <span class="n">${fmtB(x.size)}</span>${sizeBar(x.size, maxT)}</div>`).join("")}</div></div>
      <div><div class="grp">Папки</div>
        <div class="crumbs">${crumbs.map(p => `<a data-dir="${esc(p)}">${esc(p === r.root ? p : p.split("\\").pop())}</a>`).join(" › ")}</div>
        ${v.hint ? `<div class="note warn" style="margin:6px 0">${esc(v.hint)}</div>` : ""}
        <div class="typelist">${v.items.map(k => `<div class="trow"><span>${k.has_kids ? `<a data-dir="${esc(k.path)}">📁 ${esc(k.name)}</a>` : `📁 ${esc(k.name)}`}<span class="sub"> · ${k.files.toLocaleString(LOC)} файлов</span></span>
          <span class="n">${fmtB(k.size)} <a data-open="${esc(k.path)}" class="sub">открыть</a></span>${sizeBar(k.size, maxK)}</div>`).join("")}
          ${v.own_files_size > 0 ? `<div class="trow"><span class="sub">файлы прямо в этой папке</span><span class="n">${fmtB(v.own_files_size)}</span>${sizeBar(v.own_files_size, maxK)}</div>` : ""}
          ${v.more ? `<div class="sub">…и ещё ${v.more} папок поменьше</div>` : ""}</div></div>
    </div>
    <div class="grp">Самые большие файлы</div>
    <table class="t small">${r.big.slice(0, dev ? 300 : 60).map(f => `<tr><td style="width:1%">${cb("big", f.path, S.has(f.path))}</td><td class="mono" title="${esc(f.path)}">${esc(pathShort(f.path))}</td>
      <td class="sub">${esc(f.kind)}</td><td class="n">${fmtB(f.size)}</td><td class="acts"><a data-open="${esc(f.path)}">папка</a></td></tr>`).join("")}</table>
    <div class="row-tools"><button class="danger" data-sel-run="recycle" data-sel-name="big" data-sel-arg="paths" data-confirm="Отправить отмеченные файлы в Корзину? Их можно будет восстановить из Корзины.">Удалить отмеченные в Корзину</button></div>
    ${busyErr("recycle", "Удаляю…")}`);
}
function pDups(dev){
  const t = TASK.dups, r = t?.result;
  const minSel = `<label class="sub">не меньше <select id="dupMin">${[1, 10, 50, 100].map(m => `<option value="${m}" ${String(m) === (store.get("dupmin") || "1") ? "selected" : ""}>${m} МБ</option>`).join("")}</select></label>`;
  const top = `${explain("Ищет одинаковые по содержимому файлы (не просто по имени): сначала по размеру, потом сравнивает сами данные. Системные папки, Program Files и AppData не проверяются — там копии нужны программам. В каждой группе по умолчанию оставлен самый старый файл (обычно это оригинал), остальные отмечены к удалению в Корзину.")}
    <div class="row-tools">${minSel}<button class="primary" data-pick-run="dups">Выбрать папку и искать…</button>
      ${(M?.now?.disks || []).map(d => `<button data-dups-drive="${esc(d.mount)}\\">Весь диск ${esc(d.mount)}</button>`).join("")}</div>
    ${busyErr("dups", "Ищу дубликаты…")}`;
  if (!r) return pnl(head("Дубликаты", "Одинаковые файлы в разных местах") + top);
  const def = r.groups.flatMap(g => g.paths.slice(1));
  const S = sel("dups", t.finished, def);
  const free = r.groups.reduce((a, g) => a + g.paths.filter(p => S.has(p)).length * g.size, 0);
  return pnl(`${head("Дубликаты", `${esc(r.root)} · просмотрено файлов: ${r.files.toLocaleString(LOC)} · групп: ${r.groups.length} · лишнего: ${fmtB(r.waste)}`)}
    ${top}${busyErr("recycle", "Удаляю…")}
    ${r.groups.length ? r.groups.slice(0, dev ? 400 : 120).map((g, gi) => `<div class="dupg"><div class="sub">${g.paths.length} одинаковых файла по ${fmtB(g.size)}</div>
      ${g.paths.map((p, i) => `<label class="crow tight">${cb("dups", p, S.has(p), `data-dupg="${gi}"`)}<span class="mono" title="${esc(p)}">${esc(pathShort(p))}${i === 0 ? ` <span class="chip-note">самый старый</span>` : ""}</span><span class="acts"><a data-open="${esc(p)}">папка</a></span></label>`).join("")}</div>`).join("")
      + `<div class="stickybar"><span>Освободится: <b>${fmtB(free)}</b> (после очистки Корзины)</span><div class="grow"></div>
          <button class="danger" data-dups-go>Удалить отмеченные в Корзину</button></div>`
      : `<div class="note info">Дубликатов не найдено. 👍</div>`}`);
}
function pEmpty(dev){
  const t = TASK.empty, r = t?.result, rm = TASK.empty_remove?.result;
  const S = r ? sel("empty", t.finished, r.folders.map(f => f.path)) : new Set();
  return pnl(`${head("Пустые папки", r ? `${esc(r.root)} · пустых папок: ${r.total}` : "Папки, в которых нет ни одного файла")}
    ${explain("Пустые папки остаются после удаления программ и распаковки архивов. Места почти не занимают, но засоряют проводник. Системные папки и AppData не трогаются — некоторые программы ждут, что их пустая папка существует.")}
    <div class="row-tools"><button class="primary" data-pick-run="empty">Выбрать папку…</button></div>
    ${busyErr("empty", "Ищу пустые папки…")}${busyErr("empty_remove", "Удаляю…")}
    ${rm ? `<div class="note info">Удалено папок: ${rm.removed}.</div>` : ""}
    ${r ? (r.folders.length ? `<div class="rows">${r.folders.map(f => `<label class="crow tight">${cb("empty", f.path, S.has(f.path))}<span class="mono" title="${esc(f.path)}">${esc(pathShort(f.path))}${f.nested ? ` <span class="sub-inline">+${f.nested} вложенных</span>` : ""}</span><span class="acts"><a data-open="${esc(f.path)}">открыть</a></span></label>`).join("")}</div>
      <div class="row-tools"><button class="primary" data-sel-run="empty_remove" data-sel-name="empty" data-sel-arg="paths" data-confirm="Удалить отмеченные пустые папки?">Удалить отмеченные</button></div>`
      : `<div class="note info">Пустых папок нет. 👍</div>`) : ""}`);
}

// ============================================================ программы
function pUninst(dev){
  const t = TASK.programs, list = t?.result || [];
  const u = TASK.uninstall, fr = TASK.force_remove;
  const last = [u, fr].filter(x => x?.result && !x.result.leftovers_done).sort((a, b) => (b.finished || "").localeCompare(a.finished || ""))[0];
  const L = last?.result;
  const lname = last === u ? "uninstall" : "force_remove";
  // папки, где могут быть твои данные (сохранения игр, настройки, переписка), по умолчанию не отмечены
  const S = L ? sel("left", last.finished, L.leftovers.filter(i => (i.kind === "folder" && !i.data) || i.path.startsWith("HKCU")).map(i => i.path)) : new Set();
  const running = u?.status === "running";
  const now = running ? list.find(p => p.key === u.args?.key) : null;          // что удаляется сейчас
  return pnl(`${head("Удаление программ", list.length ? `установлено программ: ${list.length}` : "", `<button data-task-run="programs">Обновить список</button>`)}
    ${explain("«Удалить» запускает штатный деинсталлятор программы — как через Параметры Windows. После него ScanHub ищет, что осталось: папки в Program Files и AppData, ярлыки, ключи реестра. Остатки показываются списком — удаляешь только то, что отметишь. Для программ, чей деинсталлятор потерялся, есть «Удалить запись и остатки».")}
    ${running ? `<div class="note info"><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><div class="spin" style="width:16px;height:16px;border-width:2px"></div>
        <b>Удаляю ${esc(now?.name || "программу")}</b><span class="sub">${esc(u.progress || "")}</span><div class="grow" style="flex:1"></div>
        <button class="small" data-task-cancel="uninstall" ${u.cancel ? "disabled" : ""}>Перестать ждать</button></div>
        <div style="margin-top:6px">Следуй инструкциям в окне удаления программы. Если оно не появилось — проверь панель задач. Если окно закрыто или зависло — нажми «Перестать ждать»: ScanHub проверит, удалилась ли программа.</div></div>` : ""}
    ${taskErr("uninstall")}${taskErr("force_remove")}${busyErr("leftovers_remove", "Удаляю остатки…")}
    ${L && !running ? `<div class="pnl inner"><div style="display:flex;gap:8px;align-items:start"><h4 style="flex:1">${L.removed ? "✓ " + esc(L.name) + " удалена" : L.cancelled ? esc(L.name) + ": ожидание прервано — программа всё ещё установлена. Можно удалить снова" : esc(L.name) + (lname === "force_remove" ? ": запись не удалена" : ": программа всё ещё в списке — возможно, удаление отменили")}</h4>
       <button class="small" data-left-skip="${lname}" title="Скрыть">✕</button></div>
       ${L.retry_admin ? `<div class="note warn">Удаляльщик этой программы не смог закончить без прав администратора (так бывает, если он — скрипт .bat).
          <div style="margin-top:6px"><button class="small primary" data-task-run="uninstall" data-args="${attr({key: L.key, elevated: true})}">Удалить с правами администратора 🛡</button></div></div>` : ""}
       ${L.backup ? `<div class="sub">Запись из реестра сохранена: <code>${esc(L.backup)}</code></div>` : ""}
       ${L.leftovers.length ? `<div class="sub">Найдены остатки. Папки уйдут в Корзину, ключи реестра перед удалением сохраняются в резервную копию.</div>
         <div class="rows">${L.leftovers.map(i => `<label class="crow tight">${cb("left", i.path, S.has(i.path))}<span><b>${i.kind === "folder" ? "📁" : i.kind === "service" ? "⚙ служба" : "🔑"} ${esc(i.kind === "service" ? (i.label || i.path) : i.path)}</b> ${i.admin ? adminChip : ""}${i.data ? ` <span class="chip-warn" title="Сохранения игр, настройки, переписка — загляни в папку, прежде чем удалять">могут быть твои данные</span>` : ""}
             ${i.kind === "service" ? `<span class="sub">работает в фоне от удалённой программы · ${esc(i.exe || "")}</span>` : ""}${i.why ? `<span class="sub" style="color:var(--warn)">не удалилось: ${esc(i.why)}</span>` : ""}</span><span class="n">${i.size ? fmtB(i.size) : ""}</span></label>`).join("")}</div>
         ${rpBox()}<div class="row-tools"><button class="primary" data-left-go="${lname}" data-rp>Удалить отмеченные остатки</button>
           ${L.leftovers.some(i => i.why && i.kind === "folder") ? `<button data-left-delay="${lname}">Удалить занятое при перезагрузке 🛡</button>` : ""}
           <button data-left-skip="${lname}">Оставить как есть</button></div>`
         : `<div class="sub">Остатков не найдено. 👍</div>`}
       ${TASK.leftovers_remove?.result ? `<div class="note ${TASK.leftovers_remove.result.left?.length ? "warn" : "info"}">Удалено: ${TASK.leftovers_remove.result.removed}${TASK.leftovers_remove.result.left?.length ? ` · не удалилось: ${TASK.leftovers_remove.result.left.length} — они остались в списке выше с причиной` : ""}${(TASK.leftovers_remove.result.errors || []).length ? "<br>" + TASK.leftovers_remove.result.errors.map(esc).join("<br>") : ""}${rpNote(TASK.leftovers_remove.result)}</div>` : ""}
       ${TASK.leftovers_delay?.result ? `<div class="note info">✓ Удалится при следующей перезагрузке: папок ${TASK.leftovers_delay.result.scheduled} (файлов ${TASK.leftovers_delay.result.files || 0}).</div>` : ""}
       ${L.removed && list.some(p => p.name === L.name) ? `<div class="note info">У этой программы есть ещё одна запись — ${esc(list.filter(p => p.name === L.name).map(p => p.scope).join(", "))}. Это отдельная установка (для другого пользователя или 32-битная): удали и её, если она не нужна.</div>` : ""}</div>` : ""}
    ${busyErr("programs", "Читаю список программ…")}
    ${list.length ? `<input type="text" class="search" placeholder="Поиск: Telegram, Chrome, Steam…" spellcheck="false">
    <div class="applist">${list.map(p => `<div class="app" data-name="${esc((p.name + " " + p.publisher).toLowerCase())}">
      <span><b>${esc(p.name)}</b>${p.copies > 1 ? ` <span class="sub-inline">${esc(p.scope)}</span>` : ""}${p.protected ? ` <span class="chip-note">встроено в Windows</span>` : ""}${p.broken ? ` <span class="chip-warn">деинсталлятор потерян</span>` : ""}<span class="sub">${esc(p.publisher)}${p.version ? " · " + esc(p.version) : ""}${p.date ? " · установлена " + esc(p.date) : ""}${p.size ? " · " + fmtB(p.size) : ""}${dev ? " · " + esc(p.key) : ""}</span></span>
      <span class="acts">${p.location ? `<a data-open="${esc(p.location)}">папка</a> ` : ""}${p.protected
        ? `<button class="small" data-why-protected="${esc(p.protected)}" data-why-name="${esc(p.name)}">Почему нельзя</button>`
        : p.broken
        ? `<button class="small" data-task-run="force_remove" data-args="${attr({key: p.key})}" data-confirm="Деинсталлятор ${esc(p.name)} не найден. Убрать программу из списка установленных и поискать её остатки? Запись реестра сохранится в резервную копию.">Удалить запись и остатки</button>`
        : `<button class="small" data-task-run="uninstall" data-args="${attr({key: p.key})}" data-confirm="Удалить ${esc(p.name)}? Откроется окно удаления самой программы." ${running ? "disabled" : ""}>Удалить</button>`}</span></div>`).join("")}</div>` : ""}`);
}
const APPX_GROUPS = {ad: ["Реклама и пробные приложения", "Можно смело удалить: Windows ставит их для рекламы своих сервисов."],
  opt: ["По желанию", "Удаляй, если не пользуешься. Вернуть можно из Microsoft Store."],
  other: ["Установлено тобой или производителем", "Обычные приложения из Microsoft Store."],
  keep: ["Лучше оставить", "Нужны Windows, играм или драйверам. Удаляй, только если точно знаешь зачем."]};
function pDebloat(dev){
  const t = TASK.appx, list = t?.result || [], rm = TASK.appx_remove?.result;
  const S = sel("appx", t?.finished, list.filter(a => a.grp === "ad").map(a => a.full));
  const groups = Object.keys(APPX_GROUPS).filter(g => list.some(a => a.grp === g) && (g !== "keep" || dev || store.get("appxkeep") === "1"));
  return pnl(`${head("Встроенные приложения Windows", list.length ? `приложений из Microsoft Store: ${list.length}` : "", `<button data-task-run="appx">Обновить</button>`)}
    ${explain("Windows приходит с десятками приложений, многие из которых — реклама сервисов Microsoft и партнёров. Удаление происходит только для твоей учётной записи и ничего не ломает. Передумал — нажми «Вернуть» рядом: откроется страница приложения в Microsoft Store.")}
    ${busyErr("appx", "Читаю список приложений…")}${busyErr("appx_remove", "Удаляю приложения…")}
    ${rm ? `<div class="note ${rm.errors.length ? "warn" : "info"}">Удалено: ${rm.removed.length}.${rm.errors.length ? "<br>Не удалось:<br>" + rm.errors.map(esc).join("<br>") : ""}</div>` : ""}
    ${groups.map(g => `<div class="grp">${APPX_GROUPS[g][0]}</div><div class="sub" style="margin-top:-4px">${APPX_GROUPS[g][1]}</div>
      <div class="rows">${list.filter(a => a.grp === g).map(a => `<label class="crow">${cb("appx", a.full, S.has(a.full))}
        <span><b>${esc(a.title)}</b>${a.desc ? `<span class="sub">${esc(a.desc)}</span>` : ""}${dev ? `<span class="sub mono">${esc(a.full)}</span>` : ""}</span>
        <span class="n">${a.size ? fmtB(a.size) : ""} <a class="sub" data-launch="store:${esc(a.family)}">вернуть</a></span></label>`).join("")}</div>`).join("")}
    ${list.length && !dev ? `<label class="switch"><input type="checkbox" id="appxKeep" ${store.get("appxkeep") === "1" ? "checked" : ""}> показать и то, что лучше оставить</label>` : ""}
    ${list.length ? `<div class="stickybar"><span>Отмечено: <b>${S.size}</b></span><div class="grow"></div><button class="primary" data-sel-run="appx_remove" data-sel-name="appx" data-sel-arg="fulls" data-confirm="Удалить отмеченные приложения? Вернуть их можно из Microsoft Store." ${S.size ? "" : "disabled"}>Удалить отмеченные</button></div>` : ""}`);
}
// ---------- безопасное обновление программ: скачать → проверить на вирусы → тихо поставить
let UPD = {id: store.get("upd") || null, data: null, polling: false};
const UPD_IC = {wait: ["pending", "…"], download: ["running", ""], scan: ["running", ""], install: ["running", ""], ready: ["pending", "i"],
  done: ["clean", "✓"], held: ["threat", "!"], error: ["error", "!"], skipped: ["skipped", "–"], stopped: ["skipped", "–"]};
async function pollUpd(){
  if (UPD.polling || !UPD.id) return;
  UPD.polling = true;
  while (UPD.id) {
    try { UPD.data = await api(`/api/job?id=${UPD.id}&since=999999`) } catch { UPD = {id: null, data: null, polling: false}; store.set("upd", ""); break }
    if (PAGE === "apps" && SUB === "winget") redrawPanels();
    if (UPD.data.status !== "running") { runTask("winget", undefined, true); break }
    await new Promise(r => setTimeout(r, 1500));
  }
  UPD.polling = false;
}
async function startUpdates(ids, force){
  try {
    const r = await api("/api/updates", {ids, force: !!force});
    UPD = {id: r.id, data: null, polling: false}; store.set("upd", r.id);
    follow(r.id, true);                                   // ход — в консоли режима «Разработчик»
    pollUpd();
    return r.id;
  } catch (e) { toast("Обновление не началось", e.message, "err") }
}
function pWinget(dev){
  const t = TASK.winget, all = t?.result?.apps, j = UPD.data, running = j?.status === "running";
  const apps = all && all.filter(a => !a.ghost), ghosts = (all || []).filter(a => a.ghost);
  const ghostBox = ghosts.length && !running ? `<div class="note warn"><b>Уже удалены — осталась только запись в списке Windows: ${ghosts.length}.</b>
      Файлов этих программ нет, поэтому winget и предлагает их «обновить». Обновлять не нужно — убери запись, тогда они пропадут и отсюда, и из «Удаления программ».
      ${ghosts.length > 1 ? `<div class="row-tools" style="margin-top:8px"><button class="small primary" data-task-run="force_remove_many" data-args="${attr({keys: ghosts.map(a => a.ghost.key)})}"
        data-confirm="Убрать все ${ghosts.length} записи удалённых программ из списка установленных? Копии записей сохранятся. Для записей «для всех пользователей» появится одно окно UAC (в нём будет «Python» — это ScanHub).">Убрать все записи (${ghosts.length})</button></div>` : ""}
      <div class="checks" style="margin-top:8px">${ghosts.map(a => `<div class="check"><span class="ic ic-warn">!</span>
        <span><b>${esc(a.name)}</b><span class="sub">деинсталлятора и папки программы нет</span></span>
        <span><button class="small" data-task-run="force_remove" data-args="${attr({key: a.ghost.key})}" data-ghost="${esc(a.id)}"
          data-confirm="Убрать ${esc(a.ghost.name)} из списка установленных программ и поискать её остатки? Запись реестра сохранится в резервную копию.">Убрать запись</button></span></div>`).join("")}</div></div>` : "";
  const S = apps ? sel("upd", t.finished, apps.map(a => a.id)) : new Set();
  const stIcon = s => { const [c, x] = UPD_IC[s] || UPD_IC.wait; return `<span class="ic ic-${c}">${c === "running" ? '<div class="spin"></div>' : x}</span>` };
  const progress = j ? `<div class="pnl inner">
      <div class="head"><div><h4 style="margin:0">${running ? "Идёт обновление" : esc(j.verdict?.[1] || "Готово")}</h4>
        <div class="sub">${running ? esc(j.progress || "готовлюсь…") : "закончено " + esc((j.finished || "").replace("T", " "))}</div></div><div class="grow"></div>
        ${running ? `<button class="small" data-upd-skip>Пропустить текущую</button><button class="small danger" data-stop-job="${esc(j.id)}" data-confirm="Остановить обновление? То, что уже обновилось, останется; остальное — не трогаю.">Остановить</button>`
                  : `<button class="small" data-upd-hide>Скрыть</button>`}</div>
      ${running && /UAC/.test(j.progress || "") ? `<div class="note warn"><b>Подтверди окно UAC</b> — одно на все программы, которые ставятся «для всех пользователей».</div>` : ""}
      <div class="checks">${(j.apps || []).map(a => `<div class="check">${stIcon(a.state)}
        <span><b>${esc(a.name)}</b> <span class="sub-inline">${esc(a.version)} → ${esc(a.available)}${a.scope === "machine" ? " · для всех" : a.scope === "user" ? " · для тебя" : ""}</span>
          <span class="sub">${esc(a.label)}${a.notes?.length ? " · " + a.notes.map(esc).join(" · ") : ""}</span></span>
        <span>${a.state === "held" && !running ? `<button class="small" data-upd-force="${esc(a.id)}" data-confirm="Обновить ${esc(a.name)}, несмотря на предупреждение? Делай это, только если доверяешь программе и источнику.">Всё равно обновить</button>` : ""}</span></div>`).join("")}</div>
      ${dev ? `<div><a data-show-deep="${esc(j.id)}">Открыть полный ход в консоли</a></div>` : ""}</div>` : "";
  return pnl(`${head("Обновления программ", apps ? `устарело программ: ${apps.length}` : "", `<button data-task-run="winget" ${t?.status === "running" || running ? "disabled" : ""}>${apps ? "Проверить снова" : "Проверить"}</button>`)}
    ${explain("Устаревшие программы — частая дыра в безопасности. ScanHub обновляет их через winget (менеджер программ Windows) так: " +
      "<b>1)</b> скачивает установщик — winget сверяет его контрольную сумму с манифестом; <b>2)</b> проверяет файл до запуска: цифровая подпись, Microsoft Defender и VirusTotal по хэшу. " +
      "Если Defender нашёл угрозу или на VirusTotal ругаются 3 антивируса и больше — программа <b>придерживается</b> и не ставится; <b>3)</b> ставит тихо, без окон. " +
      "Программы «для тебя» — без прав администратора, программы «для всех» — <b>одним окном UAC на все сразу</b> (без этого Windows не даёт ставить в Program Files). Любую можно пропустить, всё — остановить.")}
    ${busyErr("winget", "Спрашиваю winget, какие программы устарели… до минуты")}
    ${progress}${ghostBox}
    ${apps == null && t?.result ? `<div class="note warn">winget не найден. Установи «Установщик приложений» из Microsoft Store.</div>` : ""}
    ${apps?.length && !running ? `<div class="rows">${apps.map(a => `<label class="crow tight">${cb("upd", a.id, S.has(a.id))}
        <span><b>${esc(a.name)}</b> <span class="sub-inline">${esc(a.version)} → <b>${esc(a.available)}</b></span>${dev ? `<span class="sub mono">${esc(a.id)}${a.source ? " · " + esc(a.source) : ""}</span>` : ""}</span><span></span></label>`).join("")}</div>
      <div class="stickybar"><span>Выбрано: <b>${S.size}</b> из ${apps.length}</span><div class="grow"></div>
        <button data-upd-all="1">Все</button><button data-upd-all="0">Ни одной</button>
        <button class="primary" data-upd-go ${S.size ? "" : "disabled"}>Проверить и обновить выбранные (${S.size})</button></div>`
      : apps && !apps.length ? `<div class="note info">${ghosts.length ? "Обновлять нечего: остались только записи удалённых программ." : "Все программы обновлены. 👍"}</div>` : ""}`);
}

// ============================================================ скорость
const GUID_MODES = {"00000000-0000-0000-0000-000000000000": "сбалансированный", "ded574b5-45a0-4f42-8737-46345c09c238": "максимальная производительность",
  "961cc777-2547-4f9d-8174-7d86181b8a7a": "энергосбережение", "3af9b8d9-7c97-431d-ad78-34a8bfea439f": "лучшая производительность"};
function pBoot(dev){
  const t = TASK.startup, r = t?.result, b = TASK.boot_trace?.result || r?.boot;
  const items = r?.items || [];
  const sec = ms => ms ? (ms / 1000).toFixed(1).replace(".", ",") + " с" : "—";
  const maxB = Math.max(...(b?.boots || []).map(x => x.total), 1);
  return pnl(`${head("Автозагрузка и время загрузки", r ? `программ в автозагрузке: ${items.filter(i => i.enabled).length} включено, ${items.filter(i => !i.enabled).length} выключено` : "", `<button data-task-run="startup">Обновить</button>`)}
    <div class="pnl inner"><h4>⏱ Как быстро загружается Windows</h4>
      ${b ? `<div class="stats big-stats"><span>последняя загрузка <b>${sec(b.last.total)}</b></span><span>до рабочего стола <b>${sec(b.last.main)}</b></span>
          <span>догрузка после входа <b>${sec(b.last.post)}</b></span><span class="sub">${esc((b.last.t || "").slice(0, 16).replace("T", " "))}</span></div>
        ${b.boots.length > 1 ? `<div class="bootbars" title="последние загрузки">${b.boots.slice().reverse().map(x => `<div style="height:${Math.max(4, x.total / maxB * 100)}%" class="${x.degraded ? "slow" : ""}" title="${esc((x.t || "").slice(0, 16).replace("T", " "))}: ${sec(x.total)}"></div>`).join("")}</div>
          <div class="sub">последние ${b.boots.length} загрузок, красным — когда Windows сама отметила загрузку как медленную</div>` : ""}
        ${b.slow_last?.length ? `<div class="grp">Что замедлило последнюю загрузку</div><table class="t small">${b.slow_last.slice(0, 10).map(x => `<tr><td>${esc(x.name)}${dev && x.file ? `<div class="sub mono">${esc(x.file)}</div>` : ""}</td><td class="n">+${sec(x.degradation)}</td></tr>`).join("")}</table>` : ""}
        <div class="sub">Обновлено ${esc((b.collected || "").replace("T", " "))}. <a data-task-run="boot_trace">обновить</a></div>`
      : `${explain("Windows записывает время каждой загрузки и то, какие программы и драйверы её замедлили. Этот журнал читается только с правами администратора — один раз подтверди окно UAC, результат сохранится.")}
         <div class="row-tools"><button class="primary" data-task-run="boot_trace">Узнать время загрузки</button></div>`}
      ${busyErr("boot_trace", "Читаю журнал загрузки… подтверди окно UAC")}</div>
    ${explain("Выключение здесь работает как в Диспетчере задач: программа остаётся установленной, просто не стартует вместе с Windows. Включить обратно можно в любой момент. Обычно смело выключают лаунчеры игр, мессенджеры и «помощники» обновлений; антивирус и драйверы (звук, тачпад, Lenovo) лучше оставить.")}
    ${busyErr("startup", "Собираю список…")}${busyErr("startup_set", "Сохраняю… для программ «для всех» появится окно UAC")}
    ${items.length ? `<div class="rows">${items.map(i => `<div class="crow">
        ${tgl(i.enabled, `data-startup="${esc(i.id)}"`, i.enabled ? "выключить автозапуск" : "включить автозапуск")}
        <span><b>${esc(i.name)}</b> <span class="sub-inline">${esc(i.where)}</span> ${i.admin ? adminChip : ""}${i.delay_ms ? ` <span class="chip-warn">замедляет загрузку на ${sec(i.delay_ms)}</span>` : ""}${i.missing ? ` <span class="chip-warn">файла нет</span>` : ""}
          <span class="sub">${i.signer ? "✓ " + esc(i.signer) : "без цифровой подписи"}${i.source === "kudu" ? " · автозапуск когда-то выключила программа Kudu — можно вернуть" : ""}</span>${dev ? `<span class="sub mono">${esc(i.cmd)}</span>` : ""}</span>
        <span class="acts">${i.exe && !i.missing ? `<a data-open="${esc(i.exe)}">папка</a>` : ""}</span></div>`).join("")}</div>` : ""}
    <div class="row-tools"><button data-launch="startup">Автозагрузка в Параметрах Windows</button>${tool("autoruns")?.ready ? `<button data-run="autoruns" data-mode="open">Открыть Autoruns</button>` : ""}</div>
    ${dev ? `<div class="grp">Полный аудит автозапуска: задачи, службы, WMI</div>${pAutoruns(dev)}` : ""}`);
}
function pGame(dev){
  const t = TASK.game, g = t?.result;
  if (!g) return pnl(head("Игровой режим", "") + busyErr("game", "Загружаю…"));
  const S = sel("game", "opts", (g.options || []).filter(o => o.rec).map(o => o.id));
  const mode = GUID_MODES[g.overlay] || "особый";
  return pnl(`${head("Игровой режим", g.active ? `включён с ${esc((g.since || "").slice(11, 16))}` : `сейчас выключен · режим питания: ${mode}`)}
    ${explain("Включай перед игрой, выключай после. ScanHub временно убирает то, что мешает играть: фоновые обновления, запись Xbox, экономию энергии. Всё, что было изменено, запоминается и возвращается кнопкой «Выключить». Сам ScanHub в фоне не работает — даже если закрыть его, настройки останутся до выключения режима.")}
    ${busyErr("game_on", "Включаю…")}${busyErr("game_off", "Возвращаю как было…")}
    ${g.active ? `<div class="note ok-note"><b>🎮 Игровой режим включён.</b><ul>${(g.log || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>
        <div class="row-tools"><button class="primary" data-task-run="game_off">Выключить и вернуть как было</button></div>`
      : `<div class="rows">${g.options.map(o => `<label class="crow">${cb("game", o.id, S.has(o.id))}<span><b>${esc(o.title)}</b> ${o.admin ? adminChip : ""}<span class="sub">${esc(o.desc)}</span></span><span></span></label>`).join("")}</div>
        <div class="row-tools"><button class="primary" data-game-on>Включить игровой режим</button><button data-launch="gaming">Игровой режим в Параметрах</button></div>
        ${g.last_log?.length ? `<div class="sub">В прошлый раз при выключении: ${g.last_log.map(esc).join(", ")}</div>` : ""}`}
    ${fpsBlock()}
    <div data-gpu-live>${gpuLiveHtml()}</div>`) + (setTimeout(fpsLiveDraw, 0), "");
}
function pMemory(dev){
  const now = M?.now, top = (M?.top_mem || []).slice(0, 8);
  return pnl(`${head("Оперативная память", now ? `занято ${(now.ram_used / GB).toFixed(1)} из ${((now.ram_total || M.static.ram_total) / GB).toFixed(0)} ГБ` : "")}
    ${explain("<b>Быстрая очистка</b> сжимает память неактивных программ — без прав администратора. <b>Полная</b> (как Mem Reduct) ещё сбрасывает системный файловый кэш и «резервную» память; её нужно один раз включить через UAC. Честно: Windows и сама отдаёт эту память программам, когда нужно. Очистка полезна, если игра или программа подтормаживает из-за забитой памяти; сразу после неё программы могут на секунду медленнее открываться.")}
    ${M ? memLine() : `<div class="sub">Собираю данные…</div>`}
    ${top.length ? `<div class="grp">Больше всего памяти занимают</div><table class="t small">${top.map(p => `<tr><td>${esc(p.name)}</td><td class="n">${fmtB(p.mem)}</td></tr>`).join("")}</table>` : ""}`);
}

// ============================================================ приватность и защита
function pPrivacy(dev){
  const t = TASK.privacy, items = (t?.result?.items || t?.result || []);
  const list = Array.isArray(items) ? items : [];
  const S = sel("priv", t?.finished, list.filter(i => i.rec && !i.applied).map(i => i.id));
  const res = TASK.privacy_apply?.result;
  return pnl(`${head("Приватность", list.length ? `выключено ${list.filter(i => i.applied).length} из ${list.length}` : "", `<button data-task-run="privacy">Обновить</button>`)}
    ${explain("Здесь только безопасные настройки: они не ломают обновления, Microsoft Store, вход в аккаунт и антивирус. Перед изменением ScanHub сохраняет исходные значения — «Вернуть как было» восстанавливает их точно. Отмеченные «🛡» попросят подтверждение администратора.")}
    ${busyErr("privacy", "Проверяю…")}${busyErr("privacy_apply", "Применяю…")}${busyErr("privacy_revert", "Возвращаю…")}
    ${res ? `<div class="note info">Готово. Некоторые изменения вступят в силу после перезапуска Проводника или выхода из системы.${rpNote(res)}</div>` : ""}
    <div class="rows">${list.map(i => `<label class="crow">${i.applied ? `<span class="ok-mark">✓</span>` : cb("priv", i.id, S.has(i.id))}
      <span><b>${esc(i.title)}</b> ${i.admin ? adminChip : ""} ${i.applied ? `<span class="chip-ok">уже выключено</span>` : i.partial ? `<span class="chip-note">частично</span>` : ""}
        <span class="sub">${esc(i.desc)}</span></span>
      <span class="acts">${i.can_revert ? `<a data-task-run="privacy_revert" data-args="${attr({ids: [i.id]})}">вернуть как было</a>` : ""}</span></label>`).join("")}</div>
    ${list.length ? `${rpBox()}<div class="row-tools"><button class="primary" data-sel-run="privacy_apply" data-sel-name="priv" data-sel-arg="ids" data-rp ${S.size ? "" : "disabled"}>Применить отмеченное (${S.size})</button>
      <button data-launch="privacy">Конфиденциальность в Параметрах</button></div>` : ""}`);
}
function pSecurity(dev){
  const t = TASK.security, items = (t?.result?.items || t?.result || []);
  const list = Array.isArray(items) ? items : [];
  const weak = list.filter(i => i.ok === false);
  const S = sel("sec", t?.finished, weak.filter(i => i.rec && i.kind === "fix").map(i => i.id));
  const res = TASK.security_apply?.result;
  const st = i => i.ok === true ? `<span class="chip-ok">включено</span>` : i.ok === false ? `<span class="chip-note">выключено</span>` : `<span class="sub">не применимо</span>`;
  const row = i => `<label class="crow">${i.ok !== false ? `<span class="ok-mark">${i.ok ? "✓" : "–"}</span>` : i.kind === "fix" ? cb("sec", i.id, S.has(i.id)) : `<span class="ok-mark" style="color:var(--warn)">!</span>`}
      <span><b>${esc(i.title)}</b> ${i.admin && i.ok === false ? adminChip : ""} ${st(i)}
        <span class="sub">${esc(i.desc)}</span></span>
      <span class="acts">${i.ok === false && i.launch ? `<button class="small" data-launch="${esc(i.launch)}">Открыть</button>` : ""}${i.can_revert ? `<a data-task-run="security_revert" data-args="${attr({ids: [i.id]})}">вернуть как было</a>` : ""}</span></label>`;
  return pnl(`${head("Защита Windows", list.length ? (weak.length ? `выключено защит: ${weak.length} из ${list.length}` : `всё включено (${list.filter(i => i.ok).length} из ${list.length})`) : "", `<button data-task-run="security">Обновить</button>`)}
    ${explain("Встроенные защиты Windows, которые часто выключены по умолчанию или выключены «твикерами». Перед изменением ScanHub сохраняет исходные значения — «вернуть как было» восстанавливает их. Пункты с кнопкой «Открыть» Windows разрешает включать только самому человеку.")}
    ${busyErr("security", "Проверяю…")}${busyErr("security_apply", "Применяю…")}${busyErr("security_revert", "Возвращаю…")}
    ${res ? `<div class="note info">Готово. Блок-лист драйверов, защита LSA и отключение компонентов заработают после перезагрузки.${rpNote(res)}</div>` : ""}
    <div class="rows">${weak.map(row).join("")}${list.filter(i => i.ok !== false).map(row).join("")}</div>
    ${weak.some(i => i.kind === "fix") ? `${rpBox()}<div class="row-tools"><button class="primary" data-sel-run="security_apply" data-sel-name="sec" data-sel-arg="ids" data-rp ${S.size ? "" : "disabled"}>Включить отмеченное (${S.size})</button>
      <button data-launch="defender">Безопасность Windows</button></div>` : `<div class="row-tools"><button data-launch="defender">Безопасность Windows</button></div>`}`);
}
function pBrowsers(dev){
  const t = TASK.browsers, r = t?.result;
  const ext = r?.extensions || [], shown = dev || store.get("brall") === "1" ? ext : ext.filter(e => e.level !== "ok");
  const ic = {bad: ["threat", "!"], warn: ["suspicious", "!"], info: ["running", "i"], ok: ["clean", "✓"]};
  const px = r?.proxy || {};
  return pnl(`${head("Браузеры", r ? `${esc(r.browsers.join(", ") || "браузеры не найдены")} · расширений: ${ext.length} · на что посмотреть: ${ext.filter(e => e.level === "bad" || e.level === "warn").length}` : "",
      `<button data-task-run="browsers" ${t?.status === "running" ? "disabled" : ""}>Проверить снова</button>`)}
    ${explain("Расширение с доступом «ко всем сайтам» видит всё, что ты открываешь: почту, банк, пароли на страницах. Магазины расширений проверяют их, но не всегда. " +
      "Опаснее всего расширения, поставленные <b>не из магазина</b> или <b>принудительно через политики</b> — так действуют угонщики браузера и рекламный мусор. " +
      "Здесь только проверка: удалить расширение можно в самом браузере — меню → «Расширения». Политики и прокси без твоего ведома — повод для глубокой проверки.")}
    ${busyErr("browsers", "Читаю профили браузеров…")}
    ${(r?.failed || []).length ? `<div class="note warn"><b>Не получилось прочитать: ${esc(r.failed.map(f => f.browser).join(", "))}</b> — расширения ${r.failed.length > 1 ? "этих браузеров" : "этого браузера"} не проверены. Закрой браузер и нажми «Проверить снова».${dev ? `<br><span class="mono">${esc(r.failed.map(f => f.browser + ": " + f.error).join("; "))}</span>` : ""}</div>` : ""}
    ${(r?.policies || []).map(p => `<div class="note warn"><b>${esc(p.browser)}: браузером управляют политики</b> (${esc(p.key)})<br>${p.items.map(i => `• ${esc(i.what)}: <span class="mono">${esc(i.value)}</span>`).join("<br>")}
      <br><span class="sub">На домашнем компьютере политики обычно ставит угонщик браузера или «оптимизатор». Если это не твой рабочий ПК — запусти глубокую проверку и AdwCleaner.</span></div>`).join("")}
    ${px.proxy ? `<div class="note warn"><b>Весь трафик Windows идёт через прокси ${esc(px.proxy)}.</b> Если это не твой VPN, Fiddler или другая знакомая программа — это перехват.</div>` : ""}
    ${px.pac ? `<div class="note warn"><b>Задан скрипт прокси (PAC):</b> <span class="mono">${esc(px.pac)}</span> — так подменяют сайты и рекламу.</div>` : ""}
    ${r && !r.policies.length && !px.proxy && !px.pac ? `<div class="note info">Политик браузеров и подмены прокси нет. 👍</div>` : ""}
    ${shown.length ? `<div class="checks">${shown.map(e => `<div class="check"><span class="ic ic-${ic[e.level][0]}">${ic[e.level][1]}</span>
      <span><b>${esc(e.name)}</b> <span class="sub-inline">${esc(e.browser)}${e.profile ? " · " + esc(e.profile) : ""}${e.enabled ? "" : " · выключено"}</span>
        <span class="sub">${e.flags.length ? esc(e.flags.join("; ")) : "из магазина, без опасных прав"}</span>
        ${dev ? `<span class="sub mono">${esc(e.id)} · ${esc(e.version)} · ${esc(e.path)}</span>` : ""}</span>
      <span>${e.path ? `<a data-open="${esc(e.path)}">папка</a>` : ""}</span></div>`).join("")}</div>` : r ? `<div class="note info">Расширений с замечаниями нет. 👍</div>` : ""}
    ${r && !dev ? `<label class="switch"><input type="checkbox" id="brAll" ${store.get("brall") === "1" ? "checked" : ""}> показать все расширения</label>` : ""}`);
}
function pCtx(dev){
  const t = TASK.ctx, r = t?.result;
  return pnl(`${head("Контекстное меню", r ? `пунктов от программ: ${r.items.length}` : "", `<button data-task-run="ctx">Обновить</button>`)}
    ${explain("Программы добавляют свои пункты в меню правой кнопки мыши: «Открыть в…», «Сканировать», «Добавить в архив». Лишние пункты загромождают меню и замедляют его появление. Выключение не удаляет программу и обратимо — включи переключатель снова. Изменения расширений видны после перезапуска Проводника.")}
    ${busyErr("ctx", "Собираю пункты меню…")}${busyErr("ctx_set", "Сохраняю… для системных пунктов появится окно UAC")}${busyErr("explorer_restart", "Перезапускаю Проводник…")}
    ${r?.win11 ? `<div class="toggle-card"><div><b>Классическое контекстное меню Windows 10</b>
      <div class="sub">В Windows 11 меню правой кнопки укороченное, а все пункты спрятаны под «Показать дополнительные параметры». Включи, чтобы сразу видеть полное меню. Нужно перезапустить Проводник.</div></div>
      ${tgl(r.classic, `data-ctx="classic|1"`)}</div>` : ""}
    ${r ? `${rpBox()}<div class="rows">${r.items.map(i => `<div class="crow">${tgl(i.enabled, `data-ctx="${esc(i.id)}"`)}
      <span><b>${esc(i.label)}</b> <span class="sub-inline">${esc(i.where)}</span> ${i.admin ? adminChip : ""}${i.exists === false ? ` <span class="chip-warn">программа удалена — пункт «мёртвый»</span>` : ""}
        <span class="sub">${esc(i.product || i.company || "")}${i.company && i.product ? " · " + esc(i.company) : ""} · ${i.kind === "verb" ? "команда" : "расширение оболочки"}</span>${dev ? `<span class="sub mono">${esc(i.exe || "")} · ${esc(i.reg || i.clsid || "")}</span>` : ""}</span><span></span></div>`).join("")}</div>
      ${r.packaged?.length ? `<div class="grp">Пункты нового меню Windows 11 от приложений</div><div class="sub">${r.packaged.map(p => esc(p.display)).join(", ")} — их добавляют сами приложения; убрать можно только удалением приложения или включив классическое меню.</div>` : ""}
      <div class="row-tools"><button data-task-run="explorer_restart" data-confirm="Перезапустить Проводник? Открытые окна папок закроются, панель задач на секунду пропадёт.">Перезапустить Проводник</button></div>` : ""}`);
}
function pFirewall(dev){
  const t = TASK.firewall, r = t?.result;
  const groups = {};
  for (const x of r?.rules || []) (groups[x.name + "|" + x.prog] ||= {...x, ids: []}).ids.push(x.id);
  const G = Object.values(groups);
  const warn = G.filter(g => g.level === "warn");
  return pnl(`${head("Брандмауэр", r ? `правил для программ: ${G.length} · с замечаниями: ${warn.length} · встроенных правил Windows: ${r.builtin} (не показаны)` : "", `<button data-task-run="firewall">Проверить снова</button>`)}
    ${explain("Брандмауэр не пускает к компьютеру подключения из сети. <b>Входящее правило</b> — исключение: «этой программе можно принимать подключения». Опасно, когда правило осталось от удалённой программы, разрешено программе из временной папки или открывает всё подряд в публичных сетях (кафе, вокзал). Выключенное правило не удаляется — его можно включить обратно.")}
    ${busyErr("firewall", "Читаю правила…")}${busyErr("firewall_set", "Сохраняю… подтверди окно UAC")}
    ${r ? `<div class="rows">${G.map(g => `<div class="crow">${tgl(g.enabled, `data-fw="${attr(g.ids)}"`)}
      <span><b>${esc(g.name)}</b> ${g.public ? `<span class="sub-inline">публичные сети</span>` : ""}${g.ids.length > 1 ? ` <span class="sub-inline">правил: ${g.ids.length}</span>` : ""}
        ${g.flags.map(f => ` <span class="chip-warn">${esc(f)}</span>`).join("")}
        <span class="sub mono">${esc(dev ? g.prog : pathShort(g.prog))}${g.port ? " · " + esc(g.port) : ""}</span></span><span></span></div>`).join("")}</div>
      <div class="row-tools"><button data-launch="firewall">Брандмауэр Windows (подробно)</button></div>` : ""}`);
}
function pRestore(dev){
  const t = TASK.restore, r = t?.result, c = TASK.restore_create?.result, en = TASK.restore_enable?.result;
  const cfree = (M?.now?.disks || []).find(x => x.mount === "C:");
  return pnl(`${head("Точки восстановления", r ? (r.enabled ? "защита системы включена" : "защита системы выключена") : "")}
    ${explain("<b>Точка восстановления</b> — снимок системных файлов, драйверов и реестра. Если после обновления, драйвера или настройки Windows начнёт сбоить, можно вернуться к точке — личные файлы при этом не меняются. ScanHub создаёт точку перед своими изменениями (галочка в каждом разделе), а свои настройки умеет откатить и без неё: исходные значения хранятся в <code>D:\\ScanHub\\data\\backups</code>.")}
    ${busyErr("restore", "Проверяю…")}${busyErr("restore_create", "Создаю точку… подтверди UAC, это 10–60 секунд")}${busyErr("restore_enable", "Включаю защиту… подтверди UAC")}
    ${c ? `<div class="note ${c.status === "ok" ? "info" : "warn"}">${c.status === "ok" ? "✓ Точка восстановления создана" : c.status === "skip" ? "Windows разрешает одну точку в сутки — сегодняшняя уже есть" : "Не получилось: " + esc(c.text)}</div>` : ""}
    ${r ? (r.enabled ? `<div class="row-tools"><button class="primary" data-task-run="restore_create">Создать точку сейчас</button><button data-launch="rstrui">Открыть восстановление системы</button><button data-launch="sysprotect">Настройки защиты</button></div>
        ${r.last ? `<div class="sub">Последняя точка от ScanHub: ${esc(r.last.replace("T", " "))}</div>` : ""}`
      : `<div class="note warn"><b>Защита системы выключена</b> — Windows не делает точек восстановления, откатить систему после неудачного обновления или драйвера будет нельзя.
          ${r.policy_off ? "<br>Выключена групповой политикой — включается администратором через gpedit." : ""}
          <br>Включение займёт до 5% диска C:${cfree ? ` (≈${fmtB(cfree.total * 0.05)}; сейчас свободно ${fmtB(cfree.total - cfree.used)})` : ""} — старые точки удаляются автоматически.</div>
        <div class="row-tools"><button class="primary" data-task-run="restore_enable" data-confirm="Включить защиту системы для диска C: и сразу создать точку восстановления? Windows попросит права администратора." ${r.policy_off ? "disabled" : ""}>Включить защиту и создать точку</button><button data-launch="sysprotect">Настройки защиты</button></div>`) : ""}
    ${en ? `<div class="note info">${en.status?.enabled ? "✓ Защита системы включена." : "Защита не включилась."} ${en.point?.status === "ok" ? "Точка создана." : esc(en.point?.text || "")}</div>` : ""}
    <label class="switch"><input type="checkbox" id="rpOn" ${rpOn() ? "checked" : ""}> Создавать точку восстановления перед изменениями ScanHub (по умолчанию включено)</label>`);
}
let SHRED = [];
function pShred(dev){
  const r = TASK.shred?.result, media = TASK.media?.result;
  return pnl(`${head("Шредер", "Удаление файлов без возможности восстановления")}
    ${explain("Обычное удаление стирает только «оглавление» — сам файл остаётся на диске, и программы восстановления его находят. Шредер сначала перезаписывает содержимое случайными данными, потом удаляет. <b>Честно о SSD:</b> на SSD контроллер сам решает, куда писать, поэтому полной гарантии нет; для SSD надёжнее шифрование диска BitLocker. На обычных жёстких дисках и флешках шредер работает.")}
    ${media?.m === "SSD" ? `<div class="note warn">Файлы лежат на SSD (${esc(media.b || "")}) — затирание не гарантирует, что данные нельзя восстановить специальным оборудованием.</div>` : ""}
    <div class="row-tools"><button data-shred-add="file">Добавить файл…</button><button data-shred-add="folder">Добавить папку…</button>${SHRED.length ? `<button data-shred-clear>Очистить список</button>` : ""}</div>
    ${SHRED.length ? `<div class="rows">${SHRED.map(p => `<div class="crow tight"><span>🗑</span><span class="mono">${esc(p)}</span><span></span></div>`).join("")}</div>
      <div class="row-tools"><button class="danger" data-shred-go>Уничтожить безвозвратно (${SHRED.length})</button></div>` : `<div class="sub">Список пуст — добавь файлы или папки.</div>`}
    ${busyErr("shred", "Уничтожаю…")}
    ${r ? `<div class="note ${r.errors.length ? "warn" : "info"}">Уничтожено файлов: ${r.shredded} (${fmtB(r.bytes)}).${r.errors.length ? "<br>" + r.errors.map(esc).join("<br>") : ""}</div>` : ""}`);
}

// ============================================================ здоровье ПК: проверки диска и брандмауэра
function diskChecks(){
  const d = TASK.sysfiles?.result?.disk;
  if (!d) return [];
  if (d.error) return [{grp: "Диски (подробно)", st: "info", title: "Не удалось проверить диски", text: d.error, action: ""}];
  const C = [];
  for (const s of d.scan || []) C.push({grp: "Диски (подробно)", st: /NoErrorsFound/i.test(s.r) ? "ok" : s.r ? "bad" : "info",
    title: /NoErrorsFound/i.test(s.r) ? `Файловая система ${s.d}: ошибок нет` : s.r ? `Файловая система ${s.d}: найдены ошибки` : `Диск ${s.d}: проверка не выполнилась`,
    text: /NoErrorsFound/i.test(s.r) ? "" : s.r ? "Нужна проверка с исправлением при перезагрузке: в терминале администратора chkdsk " + s.d + ": /f" : "", action: ""});
  for (const x of d.smart || []) {
    const wear = x.wear != null ? +x.wear : null, bad = (x.rerr || 0) + (x.werr || 0);
    C.push({grp: "Диски (подробно)", st: bad ? "bad" : wear != null && wear >= 80 ? "warn" : "ok", title: `${x.name}: ${wear != null ? `износ ${wear}%` : "состояние по SMART"}`,
      text: [x.temp ? `температура ${x.temp}°C` : "", x.hours ? `наработка ${x.hours} ч` : "", bad ? `неисправленных ошибок: ${bad} — сделай резервную копию!` : "ошибок чтения/записи нет"].filter(Boolean).join(" · "), action: ""});
  }
  if (d.trim_on != null) C.push({grp: "Диски (подробно)", st: d.trim_on ? "ok" : "warn", title: d.trim_on ? "TRIM для SSD включён" : "TRIM выключен",
    text: (d.trim_on ? "Windows сообщает SSD, какие блоки свободны — это сохраняет скорость и ресурс." : "Без TRIM SSD со временем замедляется.") + (d.optimize_last ? ` Последняя оптимизация: ${d.optimize_last}.` : ""),
    action: `<button class="small" data-task-run="trim" data-confirm="Выполнить TRIM для всех дисков сейчас? Попросит права администратора, займёт до пары минут.">Выполнить TRIM</button>`});
  return C;
}
function fwChecks(){
  const r = TASK.firewall?.result;
  if (!r) return [];
  return [{grp: "Защита", st: r.warn ? "warn" : "ok", title: r.warn ? `Правила брандмауэра с замечаниями: ${r.warn}` : "Правила брандмауэра в порядке",
    text: r.warn ? "Например, правила от удалённых программ или для программ из временных папок." : "", action: r.warn ? `<button class="small" data-go-page="privacy:firewall">Посмотреть</button>` : ""}];
}

// ============================================================ здоровье ПК: сбои и ошибки
const BSOD_ADVICE = {driver: "Обнови драйверы (видеокарта, Wi‑Fi, чипсет) и BIOS с сайта производителя ноутбука. Если сбой начался после установки программы или драйвера — удали её.",
  ram: "Проверь оперативную память: кнопка «Проверка памяти» ниже (нужна перезагрузка). Если есть разгон памяти (XMP/EXPO) — отключи его.",
  disk: "Проверь диск: «Полная проверка» с галочкой «Проверить диски подробно». Сделай резервную копию важных файлов.",
  gpu: "Обнови или переустанови драйвер видеокарты, проверь её температуру, отключи разгон.",
  hardware: "Отключи разгон, проверь температуры под нагрузкой и блок питания/зарядку. Если повторяется — проверь ОЗУ.",
  system: "Проверь системные файлы: «Полная проверка» с галочкой DISM + SFC."};
const UPD_CODES = {"0x80073d02": "приложение было открыто во время обновления — Microsoft Store повторит сам, это не страшно",
  "0x8024200b": "установщик обновления завершился с ошибкой — часто не хватает места на диске или нужна перезагрузка",
  "0x80070643": "ошибка установки — часто обновление .NET или Defender; повторная установка обычно помогает",
  "0x800f081f": "повреждено хранилище компонентов Windows — помогает восстановление DISM",
  "0x80073712": "повреждено хранилище компонентов Windows — помогает восстановление DISM",
  "0x80070002": "не найдены нужные файлы — помогает «Устранение неполадок» Центра обновления",
  "0x800f0922": "мало места в служебном разделе или мешает VPN/прокси",
  "0x80070070": "не хватает места на диске", "0x80240034": "не удалось скачать обновление — проблема с интернетом или сервером"};
const ago2 = iso => iso ? ago(iso) : "";
const DIAG_DET = [];
const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s;
// «что это за программа» — сервер присылает сразу на двух языках (appinfo.py), поэтому без перевода на лету
const aboutOf = x => x?.about?.[LANG] || x?.about?.ru || "";
const aboutHtml = x => aboutOf(x) ? `<span data-noi18n>${esc(aboutOf(x))}</span>` : "";
const kv = rows => `<table class="t small kv">${rows.filter(r => r[1] != null && r[1] !== "").map(([k, v]) => `<tr><td class="sub">${esc(k)}</td><td>${v}</td></tr>`).join("")}</table>`;
const when = t => esc(String(t || "").slice(0, 16).replace("T", " "));
function crashDet(c){
  return kv([["Программа", esc(c.app)], ["Что это", aboutHtml(c)], ["Где лежит", `<span class="mono">${esc(c.path)}</span>`], ["Сколько раз", c.count], ["Последний раз", when(c.last)],
    ["Почему", `${esc(c.what)}${c.code_desc ? " — " + esc(c.code_desc) : ""}`], ["Код", `<span class="mono">${esc(c.code)}</span>`]])
    + (c.items?.length ? `<div class="grp">Каждый вылет</div><table class="t small">${c.items.map(i => `<tr><td>${when(i.t)}</td><td>версия ${esc(i.version || "?")}</td><td class="mono">${esc(i.module)}</td><td class="mono">${esc(i.code)}</td></tr>`).join("")}</table>` : "")
    + `<div class="row-tools"><button class="small primary" data-crash-fix="${attr({app: c.app, path: c.path, count: c.count})}">Решить</button>${c.path && !/unknown/.test(c.path) ? `<button class="small" data-open="${esc(c.path)}">Открыть папку</button>` : ""}</div>`;
}
function hangDet(h){
  const typeName = {unknown: "окно перестало отвечать", quiesce: "приложение Store не «уснуло»", "cross-process": "ждала другую программу",
    "top level window is idle": "окно перестало реагировать", synchronous: "ждала долгую операцию"}[h.type] || h.type;
  const temp = /\\temp\\|\\tmp\\/i.test(h.path || "");
  return kv([["Программа", esc(h.app)], ["Что это", aboutHtml(h)], ["Где лежит", h.path ? `<span class="mono">${esc(h.path)}</span>` : "неизвестно"], ["Сколько раз", h.count], ["Последний раз", when(h.last)],
    ["Тип зависания", esc(typeName)], ["Почему так бывает", esc(cap(h.why || ""))], ["Не отвечала", h.seconds ? `${h.seconds} с, после чего её закрыли` : "неизвестно"]])
    + (temp ? `<div class="note info">Программа лежала во временной папке — обычно это установщик или распакованная на время утилита (например, сканер). Если ты её не запускал — проверь эту папку на вирусы.</div>` : "")
    + (h.items?.length > 1 ? `<div class="grp">Каждое зависание</div><table class="t small">${h.items.map(i => `<tr><td>${when(i.t)}</td><td>версия ${esc(i.version || "?")}</td><td>${i.seconds ? i.seconds + " с" : ""}</td><td>${esc(i.type)}</td></tr>`).join("")}</table>` : "")
    + (h.path ? `<div class="row-tools"><button class="small" data-open="${esc(h.path)}">Открыть папку</button></div>` : "");
}
function svcDet(s){
  return kv([["Служба", esc(s.name)], ["Сколько раз", s.count], ["Последний раз", when(s.last)], ["Насколько серьёзно", esc(s.sev?.[1] || "")]])
    + `<div class="grp">Что записала Windows</div><table class="t small">${(s.events || []).map(e => `<tr><td class="mono">событие ${e.id}</td><td>${esc(e.what)}</td><td>${e.count} раз</td></tr>`).join("")}</table>
    <div class="sub">Служба — программа, которая работает в фоне без окна (например, обновления, звук, Bluetooth). Windows пишет в журнал, если служба не запустилась или упала.</div>`;
}
// ---------- индекс стабильности: что его снизило и нормально ли это
const REL_CAT = {
  crash: ["Вылет программы", "вылетела"], hang: ["Зависание программы", "зависла"],
  update: ["Не установилось обновление", "не установилось обновление"], install: ["Не установилась программа", "не установилась программа"],
  windows: ["Сбой Windows", "сбой Windows"], shutdown: ["Внезапное выключение", "внезапное выключение"], other: ["Другой сбой", "другой сбой"]};
const fmtDay = d => new Date(d + "T12:00:00").toLocaleDateString(LOC, {day: "numeric", month: "long"});
// Сбой из журнала надёжности → [уровень, коротко, почему]. n — сколько раз то же самое было за 4 недели.
// Главное для обычного человека — сразу видно, можно ли не обращать внимания.
const REL_BENIGN = /^(TextInputHost|SearchHost|SearchApp|StartMenuExperienceHost|ShellExperienceHost|PhoneExperienceHost|Widgets|backgroundTaskHost|RuntimeBroker)\.exe$/i;
function relSev(e, n = 1){
  const c = String(e.code || "").toLowerCase();
  if (e.cat === "windows") return ["bad", "Важно", "сбой самой Windows — посмотри «Синие экраны» и «Аппаратные ошибки» в разделе «Сбои и ошибки»"];
  if (e.cat === "shutdown") return [n >= 2 ? "warn" : "info", n >= 2 ? "Стоит посмотреть" : "Не страшно, если разово", "компьютер выключился некорректно: села батарея, перегрев или его выключили кнопкой"];
  if (e.cat === "update" || e.cat === "install") {
    if (c === "0x80073d02") return ["ok", "Не страшно", "приложение было открыто во время обновления — Store обновит его сам позже"];
    if (n >= 5) return ["warn", "Стоит посмотреть", `не ставится уже ${n} раз — ${UPD_CODES[c] || "открой «Что установлено неправильно»"}`];
    return ["ok", "Не страшно", "неудачная попытка — Windows попробует ещё раз сама"];
  }
  if (e.cat === "hang") {
    if (REL_BENIGN.test(e.name || "")) return ["ok", "Не страшно", "часть Windows (поиск, клавиатура, меню «Пуск») на секунду не ответила — бывает у всех"];
    return n >= 3 ? ["warn", "Стоит посмотреть", `зависает регулярно (${n} раз за 4 недели) — обнови или переустанови программу`] : ["ok", "Не страшно", "программа один раз не отвечала, и её закрыли"];
  }
  if (e.cat === "crash") return n >= 3 ? ["warn", "Стоит посмотреть", `вылетает регулярно (${n} раз за 4 недели) — в разделе есть кнопка «Решить»`] : ["ok", "Не страшно", "разовый вылет — если не повторяется, можно забыть"];
  return ["info", "Для сведения", ""];
}
const SEV_RANK = {ok: 0, info: 1, warn: 2, bad: 3};
// сбои одного дня с одинаковой причиной — одной строкой: «не установилось обновление: WhatsApp, Telegram, Phone Link»
function stabGroup(list){
  const g = {};
  for (const {e, v} of list) {
    const what = REL_CAT[e.cat]?.[1] || "";
    const k = v[0] + "|" + v[2] + "|" + what + "|" + (v[0] === "ok" ? e.code || "" : e.name);
    const x = g[k] ||= {v, what, names: [], code: e.code || ""};
    if (!x.names.includes(e.name)) x.names.push(e.name);
  }
  return Object.values(g).sort((a, b) => SEV_RANK[b.v[0]] - SEV_RANK[a.v[0]]);
}
const sevChip = (v, title = "") => `<span class="schip schip-${v[0]}"${title || v[2] ? ` title="${esc(title || v[2])}"` : ""}>${esc(v[1])}</span>`;
function stabVerdict(v){
  if (v == null) return ["info", "нет данных", "Windows ещё не посчитала индекс — он появляется через несколько дней работы компьютера."];
  if (v >= 8) return ["ok", "отлично", "Сбоев почти нет."];
  if (v >= 6) return ["ok", "нормально", "Так выглядит обычный компьютер, на котором много работают и ставят программы: изредка что-то вылетает или не ставится обновление."];
  if (v >= 4) return ["warn", "ниже обычного", "За последние недели сбоев было много. Ниже видно, что именно их вызвало — часто это одна и та же программа или обновление."];
  return ["bad", "низкий", "Сбоев очень много. Если среди них синие экраны или внезапные выключения — это серьёзно; если в основном вылеты одной программы — дело в ней."];
}
function stabHtml(r, day){
  const stab = r.stability || [], last = stab.at(-1)?.v, rel = r.reliability, ev = rel?.events || [];
  const [lvl, word, text] = stabVerdict(last);
  const since = new Date(Date.now() - 28 * 864e5).toISOString().slice(0, 10);
  const g = {};
  for (const e of ev) if (e.d >= since) (g[e.cat + "|" + e.name] ||= {cat: e.cat, name: e.name, count: 0, last: e.d, code: e.code}).count++;
  const groups = Object.values(g).sort((a, b) => b.count - a.count || (b.last > a.last ? 1 : -1));
  const byCat = {};
  for (const x of groups) byCat[x.cat] = (byCat[x.cat] || 0) + x.count;
  const total = groups.reduce((a, x) => a + x.count, 0);
  const inst = (byCat.update || 0) + (byCat.install || 0);
  const trend = stab.length >= 4 ? stab.at(-1).v - stab.at(-4).v : 0;
  const hint = !rel ? "Нажми «Проверить снова» в разделе — ScanHub прочитает, какие сбои записала Windows, и покажет, что снизило индекс."
    : !total ? "" : byCat.windows || byCat.shutdown ? "Среди сбоев есть сбои самой Windows или внезапные выключения — их стоит разобрать в первую очередь."
    : inst >= total / 2 ? `Больше половины сбоев (${inst} из ${total}) — неудачные установки обновлений и программ. Это не поломка: Windows считает каждую неудачную попытку сбоем. Индекс поднимется сам, когда обновление установится или его перестанут предлагать.`
    : "Индекс снижают в основном программы — не Windows и не железо.";
  const sevN = {ok: 0, info: 0, warn: 0, bad: 0};
  for (const x of groups) sevN[relSev(x, x.count)[0]] += x.count;
  const sum = !total ? "" : sevN.bad ? `<div class="note bad"><b>Есть важное:</b> ${sevN.bad} ${plural3(sevN.bad, "сбой", "сбоя", "сбоев")} самой Windows — их стоит разобрать.</div>`
    : sevN.warn ? `<div class="note warn"><b>Опасного нет, но ${sevN.warn} ${plural3(sevN.warn, "сбой стоит", "сбоя стоит", "сбоев стоит")} посмотреть</b> — они повторяются. Остальные ${total - sevN.warn} — обычные мелочи.</div>`
    : `<div class="note ok-note"><b>Опасного нет.</b> ${last != null && last < 6 ? "Индекс низкий из-за мелочей: " : ""}все ${total} ${plural3(total, "сбой", "сбоя", "сбоев")} — разовые вылеты и неудачные попытки обновления. Компьютеру они не вредят, разбирать их не нужно.</div>`;
  const days = {};
  for (const e of ev) (days[e.d] ||= []).push(e);
  const prevOf = d => { const i = stab.findIndex(s => s.d === d); return i > 0 ? stab[i - 1].v : null };
  const dayList = stab.slice().reverse().filter(s => days[s.d] || s.d === day).slice(0, 30);
  return `<div class="stab-verdict lvl-${lvl}"><b>${last ?? "—"} из 10 — ${esc(word)}.</b> ${esc(text)}${trend >= 0.5 ? " Сейчас индекс растёт: последние дни сбоев меньше." : trend <= -0.5 ? " Последние дни индекс падает: появились новые сбои." : ""}</div>
    ${sum}${hint ? `<p>${esc(hint)}</p>` : ""}
    <div class="sub">Как считается: Windows ставит оценку от 1 до 10 по сбоям за последние недели. Каждый вылет, зависание, сбой Windows или неудачная установка снижает её (свежие — сильнее), а каждый день без сбоев понемногу поднимает. Это не оценка железа, а то, сколько всего ломалось.${rel ? ` Успешных установок и обновлений за это время: ${rel.ok} — они индекс не снижают.` : ""}</div>
    ${groups.length ? `<div class="grp" style="margin-top:14px">Что снизило индекс за 4 недели</div><table class="t small">${groups.slice(0, 12).map(x =>
      { const v = relSev(x, x.count); return `<tr><td>${sevChip(v)}</td><td class="sub">${esc(REL_CAT[x.cat]?.[0] || x.cat)}</td><td><b>${esc(x.name)}</b>${x.code ? ` <span class="mono sub-inline">${esc(x.code)}</span>` : ""}${v[2] ? `<div class="sub">${esc(cap(v[2]))}</div>` : ""}</td><td>${x.count}×</td><td class="sub">${esc(fmtDay(x.last))}</td></tr>` }).join("")}</table>`
      : rel ? `<p>За 4 недели Windows не записала ни одного сбоя.</p>` : ""}
    ${dayList.length ? `<div class="grp" style="margin-top:14px">По дням</div>${dayList.map(st => { const p = prevOf(st.d), dv = p == null ? 0 : +(st.v - p).toFixed(1);
      const list = (days[st.d] || []).map(e => ({e, v: relSev(e, g[e.cat + "|" + e.name]?.count || 1)}));
      const worst = list.reduce((w, x) => SEV_RANK[x.v[0]] > SEV_RANK[w] ? x.v[0] : w, "ok");
      const dayV = !list.length ? "" : worst === "bad" ? sevChip(["bad", "Важно"]) : worst === "warn" ? sevChip(["warn", "Есть что посмотреть"]) : sevChip(["ok", "День в порядке"], "Только мелочи — компьютеру не вредят");
      return `<div class="stab-day${st.d === day ? " on" : ""}"><div><b>${esc(fmtDay(st.d))}</b> · индекс ${st.v}${dv ? ` <span class="${dv < 0 ? "down" : "up"}">${dv > 0 ? "▲ +" : "▼ "}${dv}</span>` : ""} ${dayV}</div>
        ${stabGroup(list).map(x => `<div class="sub stab-ev">${sevChip(x.v)} ${esc(x.what)}: ${x.names.map(n => `<b style="color:var(--text)">${esc(n)}</b>`).join(", ")}${x.code ? ` <span class="mono">${esc(x.code)}</span>` : ""}${x.v[2] ? `<span class="stab-why">${esc(x.v[2])}</span>` : ""}</div>`).join("") || `<div class="sub">сбоев не было — индекс подрос</div>`}</div>` }).join("")}` : ""}`;
}
// ---------- итог разбора сбоев: что опасно, что стоит посмотреть, что можно не читать
let DIAG_Q = "";
const plural3 = (n, a, b, c) => { const m = n % 10, h = n % 100; return m === 1 && h !== 11 ? a : m >= 2 && m <= 4 && (h < 12 || h > 14) ? b : c };
function diagOverview(r){
  const D = [], W = [], calm = [];
  if (r.bsod.length) D.push({t: `Синие экраны: ${r.bsod.length}`, why: "компьютер аварийно перезагружался", sec: "bsod"});
  const unc = r.whea.filter(w => w.lvl <= 2);
  if (unc.length) D.push({t: `Неисправимые аппаратные ошибки: ${unc.length}`, why: "процессор, память или шина сообщили о сбое", sec: "whea"});
  else if (r.whea.length) W.push({t: `Исправленные аппаратные ошибки: ${r.whea.length}`, why: "единичные — не страшно, много — проверь разгон и питание", sec: "whea"});
  const dbad = r.disk.filter(d => d.lvl <= 2);
  if (dbad.length) D.push({t: `Ошибки диска: ${dbad.length}`, why: "сделай резервную копию важных файлов", sec: "disk"});
  else if (r.disk.length) W.push({t: `Предупреждения диска: ${r.disk.length}`, why: "проверь диск подробно", sec: "disk"});
  const sd = r.shutdowns.filter(s => !s.bugcheck);
  if (sd.length) W.push({t: `Внезапные выключения: ${sd.length}`, why: "питание, батарея, перегрев или зависание", sec: "shutdown"});
  const devs = {};
  for (const d of r.devices.filter(d => ![14, 22].includes(d.code))) (devs[(d.name || "Неизвестное устройство") + "|" + d.code] ||= {...d, n: 0}).n++;
  for (const d of Object.values(devs)) ((d.code === 12 || d.code === 43) && !d.hint ? D : W).push({t: (d.name || "Неизвестное устройство") + (d.n > 1 ? ` ×${d.n}` : ""),
    why: d.hint ? `${d.why} — скорее всего, дело в самом устройстве, кабеле или порте, а не в драйвере` : d.why, find: d.name});
  if ((r.summary || []).some(x => x.lvl === "warn" && /видеодрайвер/i.test(x.text))) W.push({t: "Видеодрайвер", why: "сбои повторяются или были недавно", sec: "gpu"});
  for (const c of r.crashes.filter(c => c.count >= 2)) W.push({t: c.app, why: `вылетала ${c.count} ${plural3(c.count, "раз", "раза", "раз")}`, find: c.app});
  for (const h of r.hangs.filter(h => h.count >= 3 && !h.benign)) W.push({t: h.app, why: `зависала ${h.count} ${plural3(h.count, "раз", "раза", "раз")}`, find: h.app});
  for (const s of r.services.filter(s => s.sev?.[0] === "warn")) W.push({t: s.name, why: "служба падает снова и снова", find: s.name});
  for (const d of r.drivers.filter(d => !d.benign)) W.push({t: `Драйвер ${d.name}`, why: "не загружается", find: d.name});
  const updFail = {};
  for (const u of r.updates) if (u.code !== "0x80073d02") updFail[u.title] = (updFail[u.title] || 0) + 1;
  const uf = Object.keys(updFail);
  if (uf.length) W.push({t: `Не устанавливаются обновления: ${uf.length}`, why: uf.slice(0, 2).map(x => x.replace(/^[0-9A-Z]{12}-/, "").replace(/\s*\(.*$/, "")).join(", ") + (uf.length > 2 ? "…" : ""), sec: "broken"});
  const miss = r.runtimes.filter(x => !x.ok && x.need);
  if (miss.length) W.push({t: `Не хватает компонентов: ${miss.length}`, why: "без них не запускаются некоторые программы и игры", sec: "runtimes"});
  if (r.lowmem.length) W.push({t: "Нехватка памяти", why: "Windows предупреждала, что памяти не хватает", sec: "lowmem"});
  const one = r.crashes.filter(c => c.count < 2).length;
  if (one) calm.push(`${one} ${plural3(one, "разовый вылет", "разовых вылета", "разовых вылетов")}`);
  const hn = r.hangs.filter(h => !(h.count >= 3 && !h.benign)).reduce((a, h) => a + h.count, 0);
  if (hn) calm.push(`${hn} ${plural3(hn, "зависание", "зависания", "зависаний")}`);
  if (r.leaks?.length) calm.push(`${r.leaks.length} ${plural3(r.leaks.length, "утечка", "утечки", "утечек")} памяти`);
  const sv = r.services.filter(s => s.sev?.[0] !== "warn").length;
  if (sv) calm.push(`${sv} ${plural3(sv, "служба упала", "службы упали", "служб упали")} по разу`);
  const st = r.updates.filter(u => u.code === "0x80073d02").length;
  if (st) calm.push(`${st} отложенных обновлений приложений Store`);
  const live = r.live.filter(l => !l.serious).reduce((a, l) => a + l.count, 0);
  if (live) calm.push(`${live} диагностических снимков ядра`);
  const [lvl, title, text] = D.length ? ["bad", "Есть серьёзные сбои", "Разбери их в первую очередь — они ниже, раскрыты."]
    : W.length ? ["warn", `Опасного нет, но ${W.length} ${plural3(W.length, "вещь", "вещи", "вещей")} стоит посмотреть`, "Повторяющиеся сбои — их причину лучше устранить."]
    : ["ok", "Опасных сбоев нет", "Всё, что ниже, — разовые и неопасные сбои. Разбираться не обязательно."];
  const item = (x, l) => `<div class="dover-i"><span class="dot ${l}"></span><span><b>${esc(x.t)}</b> <span class="why">— ${esc(x.why || "")}</span></span><button class="small" data-diag-show="${attr({find: x.find || "", sec: x.sec || ""})}">Показать</button></div>`;
  return `<div class="dover lvl-${lvl}"><div class="dover-h"><span class="ic ic-${{bad: "threat", warn: "suspicious", ok: "clean"}[lvl]}">${lvl === "ok" ? "✓" : "!"}</span><b>${esc(title)}</b><span class="sub">${esc(text)}</span></div>
    ${D.map(x => item(x, "bad")).join("")}${W.slice(0, 8).map(x => item(x, "warn")).join("")}
    ${calm.length ? `<div class="sub dover-calm">Не опасно, можно не разбираться: ${esc(calm.join(" · "))}. Эти разделы ниже свёрнуты.</div>` : ""}</div>`;
}
// все программы, службы и драйверы, которые давали сбой, — одной таблицей
function diagAll(r){
  const m = {};
  const add = (name, kind, n = 1, last = "", about = "", w = 1) => {
    if (!name) return;
    if (!/\s|\.exe$/i.test(name) && /^[\w-]+\.[\w.]+$/.test(name)) {        // пакет Store: 5319275A.WhatsAppDesktop
      name = name.split(".").pop();
      about ||= "приложение из Microsoft Store";
    }
    const k = name.toLowerCase().replace(/\.exe$/, "");
    const x = m[k] ||= {name, crash: 0, hang: 0, leak: 0, svc: 0, inst: 0, last: "", about: ""};
    x[kind] += n;
    x.score = (x.score || 0) + n * w * {crash: 5, hang: 3, inst: 2, svc: 1, leak: 1}[kind];
    if (last > x.last) x.last = last;
    if (about && !x.about) x.about = about;
  };
  for (const c of r.crashes) add(c.app, "crash", c.count, c.last, aboutOf(c));
  for (const c of r.store_crash || []) add(c.app, "crash", c.count, c.last);
  for (const h of r.hangs) add(h.app, "hang", h.count, h.last, aboutOf(h));
  for (const l of r.leaks || []) add(l.app, "leak", l.count, l.last, aboutOf(l));
  for (const s of r.services) add(s.name, "svc", s.count, s.last, "служба Windows или программы");
  for (const d of r.drivers) add(`Драйвер ${d.name}`, "svc", d.count, "", d.benign ? "частое предупреждение Windows, обычно безвредно" : "", d.benign ? 0.02 : 1);
  for (const s of r.broken_services) add(s.title || s.name, "svc", 1, "", "служба удалённой программы");
  for (const u of r.updates) add(u.title.replace(/^[0-9A-Z]{12}-/, ""), "inst", 1, u.t || "");
  for (const e of r.reliability?.events || []) if (e.cat === "install") add(e.name, "inst", 1, e.t);
  return Object.values(m).map(x => ({...x, total: x.crash + x.hang + x.leak + x.svc + x.inst}))
    .sort((a, b) => b.score - a.score || (b.last > a.last ? 1 : -1));
}
let DALL_SORT = {k: "score", dir: -1};
const DALL_COLS = [["name", "Программа", ""], ["crash", "Вылеты", "Аварийно закрылась"], ["hang", "Зависания", "Перестала отвечать"],
  ["leak", "Утечки", "Набирала память и не отдавала"], ["svc", "Службы", "Служба или драйвер не запустились или упали"],
  ["inst", "Установки", "Не установилась сама программа или её обновление"], ["last", "Последний раз", ""]];
function dallSort(rows){
  const {k, dir} = DALL_SORT;
  return rows.slice().sort((a, b) => k === "name" ? dir * a.name.localeCompare(b.name) :
    k === "last" ? (!a.last - !b.last) || dir * (a.last > b.last ? 1 : a.last < b.last ? -1 : 0) || b.score - a.score :
    dir * (a[k] - b[k]) || b.score - a.score);
}
function dallBody(rows){
  const c = n => n ? `<b>${n}</b>` : `<span class="sub">—</span>`;
  return dallSort(rows).map(x => `<tr data-diag-pick="${esc(x.name.replace(/^Драйвер /, ""))}" title="Показать сбои этой программы"><td><b>${esc(x.name)}</b>${x.about ? `<div class="sub">${esc(x.about)}</div>` : ""}</td>
      <td>${c(x.crash)}</td><td>${c(x.hang)}</td><td>${c(x.leak)}</td><td>${c(x.svc)}</td><td>${c(x.inst)}</td><td class="sub">${x.last ? esc(ago2(x.last)) : ""}</td></tr>`).join("");
}
const dallHead = () => DALL_COLS.map(([k, t, tip]) => `<th data-dall-sort="${k}" title="${esc(tip ? tip + " · " : "")}Нажми — отсортировать"${DALL_SORT.k === k ? ` class="on"` : ""}>${esc(t)}${DALL_SORT.k === k ? (DALL_SORT.dir < 0 ? " ↓" : " ↑") : ""}</th>`).join("");
function diagAllHtml(r){
  const rows = diagAll(r);
  return `<div class="sub" style="margin-bottom:8px">Всё, что за ${r.days} дней вылетало, зависало, теряло память, не запускалось или не устанавливалось. Нажми на строку — внизу останутся только сбои этой программы.</div>
    <input id="diagAllFind" type="text" placeholder="Фильтр по названию" autocomplete="off" style="width:100%;margin-bottom:8px">
    <div class="sub" style="margin-bottom:6px">Сортировка: нажми на название столбца (ещё раз — в обратную сторону). Сейчас: ${DALL_SORT.k === "score" ? "сначала самое важное" : "по столбцу «" + esc(DALL_COLS.find(c => c[0] === DALL_SORT.k)[1]) + "»"}.</div>
    <table class="t small dall"><thead><tr>${dallHead()}</tr></thead><tbody>${dallBody(rows)}</tbody></table>`;
}
document.addEventListener("input", e => {
  if (e.target.id !== "diagAllFind") return;
  const q = e.target.value.trim().toLowerCase();
  document.querySelectorAll(".dall tbody tr").forEach(tr => { tr.hidden = !!q && !tr.textContent.toLowerCase().includes(q) });
});
document.addEventListener("click", e => {
  if (e.target.closest("[data-diag-all]") && TASK.diag?.result) {
    modal({title: "Все программы со сбоями", html: diagAllHtml(TASK.diag.result), ok: "Закрыть", cancel: null, icon: "i", wide: true});
    setTimeout(() => document.getElementById("diagAllFind")?.focus(), 60);
    return;
  }
  const th = e.target.closest("[data-dall-sort]");
  if (th && TASK.diag?.result) {
    const k = th.dataset.dallSort;
    DALL_SORT = DALL_SORT.k === k ? {k, dir: -DALL_SORT.dir} : {k, dir: k === "name" ? 1 : -1};
    const box = th.closest(".mdl-html");
    if (box) {
      const q = document.getElementById("diagAllFind")?.value || "";
      box.innerHTML = diagAllHtml(TASK.diag.result);
      const inp = document.getElementById("diagAllFind");
      if (inp) { inp.value = q; inp.dispatchEvent(new Event("input", {bubbles: true})) }
    }
    return;
  }
  const all = e.target.closest("[data-diag-fold]");
  if (all) {
    const open = all.dataset.diagFold === "open";
    document.querySelectorAll("#diagList .dsec").forEach(s => { s.open = open });
    return;
  }
  const tr = e.target.closest("[data-diag-pick]");
  if (!tr) return;
  document.querySelector(".mdl-back [data-mdl]")?.click();
  DIAG_Q = tr.dataset.diagPick;
  const inp = document.getElementById("diagFind");
  if (inp) inp.value = DIAG_Q;
  diagFilter();
  setTimeout(() => document.querySelector("#diagList .check:not([hidden])")?.scrollIntoView({block: "center", behavior: "smooth"}), 200);
});
function diagFilter(){
  const box = document.getElementById("diagList");
  if (!box) return;
  const q = DIAG_Q.trim().toLowerCase();
  let n = 0;
  box.querySelectorAll(".dsec").forEach(sec => {
    let m = 0;
    sec.querySelectorAll(".check").forEach(c => {
      const ok = !q || (c.children[1]?.textContent || "").toLowerCase().includes(q);
      c.hidden = !ok;
      if (ok) m++;
    });
    sec.hidden = !!q && !m;
    sec.open = q ? m > 0 : sec.dataset.open === "1";
    n += m;
  });
  const none = document.getElementById("diagNone");
  if (none) none.textContent = !q ? "" : n ? `найдено: ${n}` : `«${DIAG_Q.trim()}» — сбоев за ${TASK.diag?.result?.days || 30} дней не найдено: программа работала без ошибок (или выбери период побольше вверху справа).`;
}
document.addEventListener("input", e => {
  if (e.target.id === "diagFind") { DIAG_Q = e.target.value; diagFilter() }
});
document.addEventListener("keydown", e => {
  if (e.target.id === "diagFind" && e.key === "Escape") { e.target.value = DIAG_Q = ""; diagFilter() }
});
document.addEventListener("click", e => {
  const st = e.target.closest("[data-stab]");
  if (st && TASK.diag?.result) {
    const day = e.target.closest("[data-stab-day]")?.dataset.stabDay;
    modal({title: "Индекс стабильности Windows", html: stabHtml(TASK.diag.result, day), ok: "Закрыть", cancel: null, icon: "i", wide: true});
    if (day) setTimeout(() => document.querySelector(".stab-day.on")?.scrollIntoView({block: "center"}), 60);
    return;
  }
  const b = e.target.closest("[data-diag-show]");
  if (!b) return;
  const o = JSON.parse(b.dataset.diagShow);
  if (o.find) {
    DIAG_Q = o.find;
    const inp = document.getElementById("diagFind");
    if (inp) inp.value = o.find;
    diagFilter();
    document.querySelector("#diagList .check:not([hidden])")?.scrollIntoView({block: "center", behavior: "smooth"});
  } else if (o.sec) {
    const sec = document.querySelector(`#diagList .dsec[data-sec="${o.sec}"]`);
    if (sec) { sec.open = true; sec.scrollIntoView({block: "start", behavior: "smooth"}) }
  }
});
function pCrash(dev){
  const t = TASK.diag, r = t?.result;
  const days = +(store.get("diagdays") || 30);
  const right = `<select id="diagDays">${[7, 30, 90].map(d => `<option value="${d}" ${d === days ? "selected" : ""}>за ${d} дней</option>`).join("")}</select>
    <button data-task-run="diag" data-args="${attr({days})}" ${t?.status === "running" ? "disabled" : ""}>${r ? "Проверить снова" : "Найти сбои"}</button>`;
  const intro = explain("Windows записывает в журналы каждый вылет программы, синий экран, сбой драйвера и аппаратную ошибку. ScanHub читает их и объясняет причину — по коду ошибки и по модулю, на котором упала программа: драйвер видеокарты, оверлей, мод, антивирус или сама программа. Точную причину знает только разработчик программы; здесь — самая вероятная и что с ней делать.");
  if (!r) return pnl(head("Сбои и ошибки", "Почему вылетают программы, были ли синие экраны и аппаратные ошибки", right) + intro + busyErr("diag", "Читаю журналы Windows… 10–30 секунд"));
  const sec = (title, body, sub = "", id = "") => { const open = /ic-threat|ic-suspicious/.test(body) || /note info/.test(body);
    return `<details class="dsec" data-sec="${id}" data-open="${open ? 1 : 0}"${open ? " open" : ""}><summary class="grp">${title}</summary>${sub ? `<div class="sub" style="margin:2px 0 6px">${sub}</div>` : ""}${body}</details>` };
  DIAG_DET.length = 0;
  const row = (lvl, title, text, right = "", det = null) => `<div class="check${det ? " det" : ""}"${det ? ` data-diag-det="${DIAG_DET.push(det) - 1}" title="Нажми — подробности"` : ""}><span class="ic ic-${{bad: "threat", warn: "suspicious", info: "running", ok: "clean"}[lvl]}">${lvl === "ok" ? "✓" : lvl === "info" ? "i" : "!"}</span>
    <span><b>${title}</b>${text ? `<span class="sub">${text}</span>` : ""}</span><span class="acts">${right}${lvl === "ok" ? "" : aiBtn(stripTags(title), stripTags(text) + (det?.ai ? " " + det.ai : ""), {source: "Здоровье ПК · Сбои и ошибки"})}</span></div>`;
  const sevLine = s => s ? `<span class="sev sev-${s[0]}">${esc(s[1])}</span>` : "";
  const stab = r.stability || [], lastStab = stab.at(-1)?.v;
  const parts = [];
  const top = [diagOverview(r)];
  if (stab.length) top.push(`<div class="stab-click" data-stab title="Нажми — что снизило индекс и нормально ли это"><div class="sub">Индекс стабильности Windows: <b style="color:var(--text)">${lastStab} из 10 — ${esc(stabVerdict(lastStab)[1])}</b>. Windows снижает его после сбоев и неудачных установок и поднимает, если всё работает. <a>Почему такой?</a></div>
    <div class="bootbars stab">${stab.map(x => `<div style="height:${x.v * 10}%" class="${x.v < 5 ? "slow" : ""}" data-stab-day="${esc(x.d)}" title="${esc(fmtDay(x.d))}: ${x.v} — нажми, что случилось в этот день"></div>`).join("")}</div></div>`);
  top.push(`<div class="dfind"><input id="diagFind" type="text" placeholder="Найти программу, службу или драйвер — например, Excel" value="${esc(DIAG_Q)}" autocomplete="off"><button class="small" data-diag-all title="Одна таблица: что вылетало, зависало, теряло память или не ставилось">Все программы со сбоями · ${diagAll(r).length}</button><span class="fold-btns"><button class="small" data-diag-fold="open" title="Раскрыть все разделы ниже">Развернуть всё</button><button class="small" data-diag-fold="close">Свернуть всё</button></span><span id="diagNone" class="sub"></span></div>`);
  if (r.bsod.length) parts.push(sec(`Синие экраны: ${r.bsod.length}`, `<div class="checks">${r.bsod.map(b => row("bad", `${esc(b.name)} <span class="sub-inline">${esc(b.code)}</span>`,
    `${esc(b.desc)}. ${esc(BSOD_ADVICE[b.cat] || "")}${dev && b.dump ? `<br><span class="mono">${esc(b.dump)}</span>` : ""}`, `<span class="sub">${esc(ago2(b.t))}</span>`)).join("")}</div>`,
    "Компьютер аварийно перезагрузился из-за критической ошибки. Код подсказывает, что виновато.", "bsod"));
  const sd = r.shutdowns.filter(s => !s.bugcheck);
  if (sd.length) parts.push(sec(`Внезапные выключения: ${sd.length}`, `<div class="checks">${sd.slice(0, 10).map(s => row("warn", s.button ? "Выключен кнопкой питания" : "Компьютер выключился некорректно",
    s.button ? "Скорее всего, компьютер завис и его выключили кнопкой." : "Пропало питание, разрядилась батарея, сработала защита от перегрева или компьютер завис.", `<span class="sub">${esc(ago2(s.t))}</span>`)).join("")}</div>`, "", "shutdown"));
  if (r.whea.length) parts.push(sec(`Аппаратные ошибки: ${r.whea.length}`, `<div class="checks">${r.whea.slice(0, 10).map(w => row(w.lvl <= 2 ? "bad" : "warn", w.lvl <= 2 ? "Неисправимая аппаратная ошибка" : "Исправленная аппаратная ошибка",
    esc(w.text), `<span class="sub">${esc(ago2(w.t))}</span>`)).join("")}</div>`,
    "Процессор, память или шина PCIe сообщили об ошибке. Единичные исправленные — не страшно; много или неисправимые — проблема с железом, разгоном или питанием.", "whea"));
  if (r.gpu.length || r.live.length) parts.push(sec("Видеокарта и графика", `<div class="checks">
    ${r.gpu.slice(0, 6).map(g => row("warn", "Видеодрайвер перестал отвечать и был перезапущен", "Экран мигнул или игра вылетела. Если повторяется — обнови драйвер, проверь температуру, отключи разгон.", `<span class="sub">${esc(ago2(g.t))}</span>`)).join("")}
    ${r.live.map(l => row(l.serious ? "warn" : "info", `Диагностические снимки ядра ${esc(l.code)}: ${l.count}`, esc(l.desc) + (l.serious ? "" : ". Снимки копятся на диске C: — их можно удалить в «Очистке» (пункт «Диагностические снимки ядра»)."),
      l.serious ? "" : `<button class="small" data-go-page="clean:junk">Очистка</button>`)).join("")}</div>`, "", "gpu"));
  if (r.disk.length) parts.push(sec(`Ошибки диска: ${r.disk.length}`, `<div class="checks">${r.disk.slice(0, 8).map(d => row(d.lvl <= 2 ? "bad" : "warn", `${esc(d.prov)} (событие ${d.id})`, esc(d.text), `<span class="sub">${esc(ago2(d.t))}</span>`)).join("")}</div>`,
    "Ошибки чтения или записи — сделай резервную копию важных файлов и проверь диск («Полная проверка» → «Проверить диски подробно»).", "disk"));
  parts.push(sec(`Вылеты программ: ${r.crashes.reduce((a, c) => a + c.count, 0)}`, r.crashes.length ? `<div class="checks">${r.crashes.map(c => row(c.count >= 3 ? "warn" : "info",
    `${esc(c.app)} <span class="sub-inline">${c.count} ${c.count === 1 ? "раз" : "раза"}</span>`,
    `${aboutOf(c) ? `<b style="font-weight:600">Что это:</b> ${aboutHtml(c)}<br>` : ""}<b style="font-weight:600">Почему:</b> ${esc(c.what)}${c.code_name ? ` · ${esc(c.code_name)}` : ""}${c.code_desc ? ` — ${esc(c.code_desc)}` : ""}.<br><b style="font-weight:600">Что делать:</b> ${esc(c.advice)}
     ${sevLine(c.count >= 3 ? ["warn", "Стоит посмотреть: вылетает регулярно — нажми «Решить»"] : c.count === 2 ? ["info", "Не страшно, если больше не повторится"] : ["info", "Не опасно: разовый вылет — если не повторяется, можно забыть"])}
     ${dev ? `<br>модули: <span class="mono">${esc(c.modules.join(", "))} · ${esc(c.code)} · ${esc(c.path)}</span>` : ""}`,
    `<span class="sub">${esc(ago2(c.last))}</span><button class="small primary" data-crash-fix="${attr({app: c.app, path: c.path, count: c.count})}" title="Что можно сделать именно с этой программой">Решить</button>`,
    {title: `Вылеты ${c.app}`, html: crashDet(c), ai: `Путь: ${c.path}. Код: ${c.code}. Модуль: ${c.module}. Что это: ${c.about?.ru || "?"}`})).join("")}</div>` : `<div class="note info">Программы не вылетали. 👍</div>`));
  if (r.store_crash.length) parts.push(sec("Вылеты приложений из Microsoft Store", `<div class="checks">${r.store_crash.map(c => row("info", `${esc(c.app)} <span class="sub-inline">${c.count}</span>`, "Попробуй «Параметры → Приложения → … → Исправить», затем «Сбросить».", `<span class="sub">${esc(ago2(c.last))}</span>`)).join("")}</div>`));
  if (r.hangs.length) parts.push(sec(`Зависания: ${r.hangs.reduce((a, h) => a + h.count, 0)}`, `<div class="checks">${r.hangs.map(h => row(h.count >= 3 ? "warn" : "info",
    `${esc(h.app)} <span class="sub-inline">${h.count} ${h.count === 1 ? "раз" : "раза"}</span>`,
    `${aboutOf(h) ? `<b style="font-weight:600">Что это:</b> ${aboutHtml(h)}<br>` : ""}${h.why ? esc(cap(h.why)) + "." : ""}${h.seconds ? ` Не отвечала ${h.seconds} с.` : ""}`
      + sevLine(h.benign ? ["info", "Не опасно"] : h.count >= 3 ? ["warn", "Стоит посмотреть: зависает регулярно — обнови или переустанови программу"] : ["info", "Единичное зависание — скорее всего, случайность"]),
    `<span class="sub">${esc(ago2(h.last))}</span>`, {title: `Зависания ${h.app}`, html: hangDet(h), ai: `Путь: ${h.path}. Тип зависания: ${h.type}.`})).join("")}</div>`,
    "Программа перестала отвечать, и её закрыли. Нажми на строку — увидишь, где лежит программа, сколько она не отвечала и почему так бывает."));
  const leaks = (r.leaks || []).filter(l => l && typeof l === "object" && l.count != null);
  if (leaks.length) parts.push(sec("Утечки памяти", `<div class="checks">${leaks.map(l => row("info", `${esc(l.app)}${l.count > 1 ? ` <span class="sub-inline">${l.count} раза</span>` : ""}`,
      (aboutOf(l) && !l.scanhub ? `<b style="font-weight:600">Что это:</b> ${aboutHtml(l)}<br>` : "") + (l.scanhub ? "Это сканер ScanHub или Python (на нём работает сам ScanHub): во время проверки им по делу нужно много памяти. Не обращай внимания."
        : "Программа долго набирала всё больше памяти и не отдавала её." + sevLine(["info", "Не опасно, если компьютер не тормозит. Тормозит после долгой работы — закрой и открой эту программу заново"])),
      `<span class="sub">${esc(ago2(l.last))}</span>`)).join("")}</div>`,
    "«Утечка памяти» — ошибка в программе: она берёт память и забывает её вернуть, поэтому со временем занимает всё больше. Windows замечает такое и записывает. Это не вирус и не поломка компьютера; помогает перезапуск программы, а если повторяется — её обновление."));
  const bad = r.devices.filter(d => d.code !== 22);
  const svcHtml = r.services.map(s => row(s.sev?.[0] === "warn" ? "warn" : "info", esc(s.name), esc(s.why) + (s.count > 1 ? ` (${s.count} раз)` : "") + sevLine(s.sev),
    `<span class="sub">${esc(ago2(s.last))}</span>`, {title: `Служба «${s.name}»`, html: svcDet(s)})).join("");
  const drvHtml = r.drivers.map(d => row(d.benign ? "info" : "warn", `Драйвер ${esc(d.name)} не загрузился ×${d.count}`, d.benign ? "Частое предупреждение Windows, обычно безвредно." : `Устройство ${esc(d.device)} — переустанови или обнови его драйвер.`)).join("");
  const devG = {};
  for (const d of bad) (devG[(d.name || "") + "|" + d.code] ||= {...d, n: 0}).n++;
  const devHtml = Object.values(devG).map(d => row(d.code === 14 ? "info" : (d.code === 12 || d.code === 43) && !d.hint ? "bad" : "warn", esc(d.name || "Неизвестное устройство") + (d.n > 1 ? ` <span class="sub-inline">×${d.n}</span>` : ""), `${esc(d.why)}${d.code === 12 ? " — два устройства претендуют на одни ресурсы; обнови BIOS и драйверы чипсета" : ""}`
      + (d.hint ? `<div class="dev-hint">${esc(d.hint)}</div>` : "")
      + sevLine(d.code === 14 ? ["info", "Не ошибка: Windows ждёт перезагрузки, чтобы закончить установку. Если не уходит — смотри «Комплектующие»"] : d.code === 22 ? ["info", "Не опасно: устройство выключено вручную"] : ["warn", "Устройство не работает, пока это не исправить"]),
    `<button class="small" data-go-page="health:drivers">Драйверы</button>`)).join("");
  const brokenHtml = r.broken_services.map(s => row("info", `Служба «${esc(s.title || s.name)}»`, `её программы больше нет (${esc(s.exe)}) — служба осталась после удаления и при запуске выдаёт ошибку`)).join("");
  const upd = {};
  for (const u of r.updates) (upd[u.title + "|" + u.code] ||= {...u, count: 0}).count++;
  const updHtml = Object.values(upd).map(u => row(u.code === "0x80073d02" ? "info" : "warn", `${esc(u.title.replace(/^[0-9A-Z]{12}-/, ""))} <span class="sub-inline">${esc(u.code)}${u.count > 1 ? " ×" + u.count : ""}</span>`,
    esc(UPD_CODES[u.code] || "обновление не установилось — Windows попробует ещё раз"))).join("");
  const inst = {};
  for (const e of r.reliability?.events || []) if (e.cat === "install") (inst[e.name] ||= {name: e.name, n: 0, t: e.t}).n++;
  const instHtml = Object.values(inst).map(x => row("info", `${esc(x.name)} <span class="sub-inline">не установилась${x.n > 1 ? " ×" + x.n : ""}</span>`,
    "Установщик программы завершился с ошибкой. Если программа сейчас работает — значит, со следующей попытки всё встало; если нет — скачай установщик заново и запусти от администратора.",
    `<span class="sub">${esc(ago2(x.t))}</span>`)).join("");
  const rank = h => /ic-threat/.test(h) ? 0 : /ic-suspicious/.test(h) ? 1 : 2;
  const brokenRows = [devHtml, brokenHtml, svcHtml, drvHtml, updHtml, instHtml].join("").split(/(?=<div class="check)/).filter(Boolean).sort((a, b) => rank(a) - rank(b));
  if (brokenRows.length) parts.push(sec("Что установлено неправильно или работает с ошибками",
    `<div class="checks">${brokenRows.join("")}</div>`, "Устройства, службы, драйверы и обновления, которые не смогли запуститься или установиться. Сначала — то, что стоит посмотреть.", "broken"));
  if (r.lowmem.length) parts.push(sec("Нехватка памяти", `<div class="checks">${r.lowmem.slice(0, 5).map(l => row("warn", "Windows предупреждала о нехватке памяти", esc(l.text), `<span class="sub">${esc(ago2(l.t))}</span>`)).join("")}</div>`, "", "lowmem"));
  const miss = r.runtimes.filter(x => !x.ok && x.need);
  if (miss.length) parts.push(sec("Не хватает компонентов", `<div class="checks">${miss.map(x => row("warn", esc(x.name), esc(x.desc), x.winget ? `<button class="small primary" data-launch="winget_install:${esc(x.winget)}">Установить</button>` : "")).join("")}</div>`, "", "runtimes"));
  const tools = `<div class="wintools"><span class="sub">Ещё:</span>
      <button class="small" data-ai-ask="Посмотри журналы Windows за последнюю неделю: есть ли что-то, на что стоит обратить внимание?" title="Помощник сам прочитает журналы и объяснит простыми словами">✦ Спросить помощника про журналы</button>
      <button class="small" data-launch="perfmon_rel" title="График стабильности Windows по дням: что и когда ломалось">Монитор стабильности</button>
      <button class="small" data-launch="mdsched" data-confirm="Проверка памяти Windows попросит перезагрузить компьютер и займёт 10–20 минут. Открыть?" title="Проверка оперативной памяти при перезагрузке — если были синие экраны">Проверка памяти</button>
      <button class="small" data-go-page="health:runtimes" title="Visual C++, DirectX, .NET — без них не запускаются программы и игры">Компоненты для программ</button>
      ${dev ? `<button class="small" data-launch="eventvwr" title="Журнал событий Windows — для опытных">Журнал событий</button>` : ""}</div>`;
  return pnl(`${head("Сбои и ошибки", `за ${r.days} дней · проверено ${esc((r.collected || "").replace("T", " "))}`, right)}
    ${intro}${tools}${busyErr("diag", "Читаю журналы Windows…")}
    ${top.join("")}<div id="diagList">${parts.join("")}</div>`) + (setTimeout(diagFilter, 0), "");
}
function pRuntimes(dev){
  const t = TASK.runtimes, items = t?.result?.items || [];
  return pnl(`${head("Компоненты для программ и игр", items.length ? `установлено ${items.filter(x => x.ok).length} из ${items.length}` : "", `<button data-task-run="runtimes">Проверить снова</button>`)}
    ${explain("Многие программы и игры не несут всё нужное с собой и рассчитывают на общие компоненты Windows: Visual C++, DirectX, .NET. Если компонента нет, программа не запускается с ошибкой «не найден …dll» или вылетает при старте. Установка открывается в отдельном окне через winget — официальный менеджер программ Windows.")}
    ${busyErr("runtimes", "Проверяю…")}
    <div class="checks">${items.map(x => `<div class="check"><span class="ic ic-${x.ok ? "clean" : x.need ? "suspicious" : "pending"}">${x.ok ? "✓" : x.need ? "!" : "i"}</span>
      <span><b>${esc(x.name)}</b>${x.ver ? ` <span class="sub-inline">${esc(x.ver)}</span>` : ""}<span class="sub">${esc(x.desc)}</span></span>
      <span>${x.ok ? "" : x.winget ? `<button class="small${x.need ? " primary" : ""}" data-launch="winget_install:${esc(x.winget)}">Установить</button>` : x.launch ? `<button class="small" data-launch="${esc(x.launch)}">Открыть</button>` : ""}</span></div>`).join("")}</div>`);
}
let ALERTS = [], ALERT_LAST = null, ALERT_INFO = null;
function pAlerts(dev){
  const on = ALERT_INFO?.on !== false, w = TASK.watch?.result;
  return pnl(`${head("Предупреждения", on ? "включены" : "выключены")}
    ${explain("ScanHub сам замечает странное в работе устройства и сообщает: внизу окна, а если ScanHub свёрнут — уведомлением Windows. Наблюдение идёт, только пока ScanHub открыт (можно свернуть). Каждое предупреждение повторяется не чаще раза в 15–30 минут.")}
    <div class="toggle-card"><div><b>Предупреждать, пока открыт ScanHub</b><div class="sub">Проверка раз в 10 секунд по уже собираемым данным — почти не нагружает компьютер.${ALERT_INFO?.checked ? ` Последняя проверка: ${esc(ALERT_INFO.checked.slice(11))}.` : ""}</div></div>
      ${tgl(on, `data-alerts-on`)}</div>
    <div class="grp">Что отслеживается</div>
    <div class="checks">${(ALERT_INFO?.rules || []).map(r => `<div class="check"><span class="ic ic-running">i</span><span><b>${esc(r.title)}</b><span class="sub">${esc(r.desc)}</span></span><span></span></div>`).join("")}</div>
    <div class="toggle-card"><div><b>Когда ScanHub закрыт — «Сторож»</b>
      <div class="sub">Раз в 15 минут на 40 секунд проверяет майнеры, перегрев, место на дисках и новые сбои (вылеты, синие экраны, аппаратные ошибки) и присылает уведомление Windows. Это задача планировщика, а не постоянная программа.</div>
      <div class="sub">${w ? (w.enabled ? "✓ включён" : "выключен") : "проверяю…"}</div>${taskErr("watch_set")}</div>
      <button class="${w?.enabled ? "" : "primary"}" data-task-run="watch_set" data-args='{"enable":${!w?.enabled}}'>${w?.enabled ? "Выключить" : "Включить"}</button></div>
    <div class="grp">Последние предупреждения</div>
    ${ALERTS.length ? `<div class="checks">${ALERTS.slice(0, 50).map(a => `<div class="check"><span class="ic ic-${a.level === "bad" ? "threat" : "suspicious"}">!</span>
      <span><b>${esc(a.title)}</b><span class="sub">${esc(a.text)}</span></span><span class="sub">${esc(a.t.slice(11, 16))}</span></div>`).join("")}</div>`
      : `<div class="sub">Пока ничего не случилось.</div>`}
    ${w?.alerts?.length ? `<div class="grp">Срабатывания «Сторожа»</div><div class="checks">${w.alerts.slice(0, 10).map(a => `<div class="check"><span class="ic ic-suspicious">!</span><span><b>${esc(a.time)}</b><span class="sub">${a.found.map(esc).join("<br>")}</span></span><span></span></div>`).join("")}</div>` : ""}`);
}
async function pollAlerts(){
  try {
    const r = await api(`/api/alerts?since=${ALERT_LAST ?? 0}`);
    ALERT_INFO = r;
    const fresh = r.items.filter(a => !ALERTS.some(x => x.id === a.id));
    ALERTS = fresh.concat(ALERTS).slice(0, 200);
    if (ALERT_LAST !== null) for (const a of fresh) toast(a.title, a.text, a.level === "bad" ? "err" : "warn", 15000, () => {
      if (a.action?.page) { const [p, s] = a.action.page.split(":"); go(p, s) }
      else if (a.action?.scan) { go("scan", "check"); scanBatch(a.action.scan, TOOLS.filter(t => t.ready && !t.data_missing && t.modes.some(m => m.multi))).then(b => { simpleBatch = b; renderSimpleResult() }) }
    });
    ALERT_LAST = r.last;
    if (fresh.length && PAGE === "health" && SUB === "alerts") redrawPanels();
  } catch {}
}
setInterval(pollAlerts, 5000);

// ============================================================ панели: реестр, подготовка, перерисовка
function panelHtml(name, dev){
  const f = {deep: pDeep, apps: pApps, quar: pQuar, network: pNetwork, junk: pJunk, shortcuts: pShortcuts, drvstore: pDrvStore, envpath: pEnvPath,
    disk: pDisk, dups: pDups, empty: pEmpty, uninst: pUninst, debloat: pDebloat, winget: pWinget, boot: pBoot, game: pGame, memory: pMemory,
    noise: pNoise, privacy: pPrivacy, security: pSecurity, browsers: pBrowsers, ctx: pCtx, firewall: pFirewall, restore: pRestore, miners: pProtect, shred: pShred, changes: pChanges,
    health: pHealth, drivers: pDrivers, hw: pHw, history: pHistory, net: pNet, crash: pCrash, runtimes: pRuntimes, alerts: pAlerts, ultra: pUltra, devices: pDevices, phone: pPhone}[name];
  return f ? f(dev) : "";
}
function prepPanel(name){
  const auto = {drivers: "drivers", miners: ["hosts", "watch"], network: "network", apps: "apps", hw: ["hwcheck", "hardware"], quar: "quarantine_list",
    junk: "junk_scan", shortcuts: "shortcuts", drvstore: "drvstore", envpath: "envpath", uninst: "programs", debloat: "appx", winget: "winget",
    boot: "startup", game: "game", privacy: "privacy", security: "security", browsers: "browsers", ctx: "ctx", firewall: "firewall", restore: "restore", crash: "diag", runtimes: "runtimes",
    alerts: "watch", history: "health_history", devices: "devices", phone: "phone_status"}[name];
  if (name === "phone") runTask("phone_last", undefined, true);
  if (name === "game") fpsPoll();      // последний итог с диска — всегда свежий
  if (name === "changes") runTask("changes", undefined, true);      // журнал всегда свежий: изменения делаются в других разделах
  if (name === "alerts") pollAlerts().then(redrawPanels);
  if (name === "ultra") { ULTRA.seen = true; if (!ULTRA.polling) loadUltra() }
  [].concat(auto || []).forEach(n => ensureTask(n));
  if (["envpath", "drvstore", "privacy", "security", "ctx", "uninst"].includes(name)) ensureTask("restore");
  const manual = {health: ["health", "sysfiles", "firewall"], autoruns: ["autoruns"], boot: ["autoruns", "boot_trace"], drivers: ["driver_updates"], noise: ["noise"],
    disk: ["disk_analyze"], dups: ["dups"], empty: ["empty"], shred: ["shred"]}[name] || [];
  manual.forEach(async n => {
    if (TASK[n]) return;
    const t = await api(`/api/task?name=${n}`);
    if (t.status !== "none") { TASK[n] = t; redrawPanels(); if (t.status === "running") runTask(n, undefined, true) }
  });
  if (["disk", "dups", "restore", "memory"].includes(name) && !M) api("/api/metrics").then(m => { M = m; redrawPanels() }).catch(() => {});
}
function redrawPanels(){
  if (viewFor() !== "panel") return;
  const box = $("#panelBox");
  const keep = box.querySelector("input.search")?.value, focused = document.activeElement?.matches?.("input.search");
  const y = window.scrollY;
  const inner = [...box.querySelectorAll(".applist,.typelist,.rows,.checks")].map(e => e.scrollTop);
  box.innerHTML = panelHtml(SUB || PAGE, MODE === "dev");
  box.querySelectorAll(".applist,.typelist,.rows,.checks").forEach((e, k) => { if (inner[k]) e.scrollTop = inner[k] });
  const i = box.querySelector("input.search");
  if (i && keep) { i.value = keep; filterApps(i) }
  if (i && focused) i.focus();
  if (Math.abs(window.scrollY - y) > 2) window.scrollTo({top: y});
}
// старые имена (из прежней версии интерфейса)
function openPanel(name){ goPanel(name) }
function showSys(name){ goPanel(name) }

// ============================================================ уведомления о задачах (новые)
function taskToast2(name, t, args){
  const r = t.result || {};
  const rp = r.restore_point?.status === "ok" ? " · точка восстановления создана" : "";
  const m = {
    junk_clean: () => [`Освобождено ${fmtB(r.freed || 0)}`, (r.errors?.length ? "часть не удалось: " + r.errors[0] : r.skipped ? `пропущено занятых файлов: ${r.skipped}` : "мусор удалён"), r.errors?.length ? "warn" : "ok"],
    disk_analyze: () => ["Анализ диска готов", `${fmtB(r.size)} · ${r.files?.toLocaleString(LOC)} файлов`],
    dups: () => [r.groups?.length ? `Найдено групп дубликатов: ${r.groups.length}` : "Дубликатов нет", r.waste ? `лишнего: ${fmtB(r.waste)}` : ""],
    empty: () => [`Пустых папок: ${r.total ?? 0}`, ""], empty_remove: () => [`Удалено папок: ${r.removed}`, ""],
    recycle: () => [`В Корзину: ${r.removed}`, r.errors?.length ? `не удалось: ${r.errors.length}` : "место освободится после очистки Корзины", r.errors?.length ? "warn" : "ok"],
    shortcuts_remove: () => [`Удалено ярлыков: ${r.removed}`, "копии сохранены"], envpath_fix: () => ["PATH очищен", "терминалы увидят изменения после перезапуска" + rp],
    app_links_create: () => [r.ok ? "Ярлык создан" : "Ярлык создан не везде", "на рабочем столе и в меню «Пуск»", r.ok ? "ok" : "warn"],
    net_diag: () => [r.verdict || "Проверка интернета готова", "подробности — в «Скорость → Интернет»", /в порядке/.test(r.verdict || "") ? "ok" : "warn"],
    driver_disable: () => ["Драйвер отключён", "перестанет загружаться после перезагрузки компьютера"],
    driver_restore: () => ["Драйвер включён обратно", "снова будет загружаться при включении компьютера"],
    drvstore_remove: () => [`Удалено старых драйверов: ${r.removed}`, (r.failed?.length ? `не удалось: ${r.failed.length}` : "") + rp, r.failed?.length ? "warn" : "ok"],
    shred: () => [`Уничтожено файлов: ${r.shredded}`, r.errors?.length ? `ошибок: ${r.errors.length}` : fmtB(r.bytes), r.errors?.length ? "warn" : "ok"],
    uninstall: () => [r.removed ? `${r.name} удалена` : `${r.name}: удаление не завершено`, r.leftovers?.length ? `найдено остатков: ${r.leftovers.length}` : "остатков нет", r.removed ? "ok" : "warn"],
    force_remove_many: () => [`Убрано записей: ${r.removed || 0}`, r.failed?.length ? `не получилось: ${r.failed.join(", ")}` : "копии сохранены", r.failed?.length ? "warn" : "ok"],
    force_remove: () => [`${r.name}: запись удалена`, r.leftovers?.length ? `найдено остатков: ${r.leftovers.length}` : "остатков нет"],
    leftovers_remove: () => [`Остатки удалены: ${r.removed}`, (r.errors?.length ? r.errors[0] : "") + rp, r.errors?.length ? "warn" : "ok"],
    appx_remove: () => [`Удалено приложений: ${r.removed?.length || 0}`, r.errors?.length ? `не удалось: ${r.errors.length}` : "вернуть можно из Microsoft Store", r.errors?.length ? "warn" : "ok"],
    prepare: () => [r?.errors?.length ? "ScanHub подготовлен не полностью" : r?.stopped ? "Подготовка остановлена" : "ScanHub готов к работе",
      r?.errors?.length ? r.errors.join("; ") : r?.done?.length ? "готово: " + r.done.join(", ") : "всё уже было на месте", r?.errors?.length ? "warn" : "ok"],
    privacy_apply: () => ["Настройки приватности применены", "исходные значения сохранены" + rp], privacy_revert: () => ["Возвращено как было", "", "info"],
    security_apply: () => ["Защита Windows усилена", "часть настроек заработает после перезагрузки" + rp], security_revert: () => ["Возвращено как было", "", "info"],
    ctx_set: () => [args.enable ? "Пункт меню включён" : "Пункт меню выключен", "увидишь после перезапуска Проводника" + rp],
    explorer_restart: () => ["Проводник перезапущен", ""],
    game_on: () => ["🎮 Игровой режим включён", (r.log || []).slice(0, 2).join(", ")], game_off: () => ["Игровой режим выключен", "всё возвращено как было", "info"],
    firewall_set: () => [args.enable ? "Правило брандмауэра включено" : "Правило брандмауэра выключено", ""],
    startup_set: () => [args.enable ? "Автозапуск включён" : "Автозапуск выключен", "сработает при следующем входе в Windows"],
    boot_trace: () => [`Последняя загрузка: ${((r.last?.total || 0) / 1000).toFixed(1)} с`, r.slow_last?.length ? `замедляли: ${r.slow_last.length}` : ""],
    restore_create: () => r.status === "ok" ? ["Точка восстановления создана", ""] : ["Точка не создана", r.text || "", "warn"],
    restore_enable: () => [r.status?.enabled ? "Защита системы включена" : "Защита не включилась", r.point?.status === "ok" ? "точка восстановления создана" : "", r.status?.enabled ? "ok" : "warn"],
    trim: () => [`TRIM выполнен: ${(r.ok || []).join(", ") || "—"}`, ""],
    quarantine: () => [`В карантине: ${r.moved}`, r.errors?.length ? r.errors[0] : "файлы обезврежены", r.errors?.length ? "warn" : "ok"],
    change_undo: () => ["Изменение отменено", "ScanHub вернул как было"],
    q_restore: () => ["Файл возвращён", r.path || "", "info"], q_delete: () => ["Файл удалён из карантина", "", "info"],
    winget: () => [r.apps == null ? "winget не найден" : r.apps.length ? `Устарело программ: ${r.apps.length}` : "Все программы обновлены", ""],
    diag: () => [r.summary?.length ? "Найдены сбои: " + r.summary.slice(0, 2).map(x => x.text.toLowerCase()).join(", ") : "Серьёзных сбоев нет", `за ${r.days} дней`, r.summary?.some(x => x.lvl === "bad") ? "warn" : "ok"],
    runtimes: () => [(r.items || []).some(x => !x.ok && x.need) ? "Не хватает компонентов" : "Все нужные компоненты установлены", ""],
    device_fix: () => ["Исправлено", "настройка Windows изменена — проверь устройство ещё раз"],
    browsers: () => { const n = (r.extensions || []).filter(e => e.level === "bad" || e.level === "warn").length + (r.policies || []).length;
      return [n ? `Браузеры: на что посмотреть — ${n}` : "Браузеры в порядке", `расширений: ${(r.extensions || []).length}`, n ? "warn" : "ok"] },
  }[name];
  if (!m) return;
  const [title, text, kind] = m();
  toast(title, text, kind || "ok");
}
// ============================================================ ПРИВАТНОСТЬ → ЧТО ИЗМЕНИЛ SCANHUB: журнал и отмена
function pChanges(dev){
  const t = TASK.changes, items = t?.result?.items || [];
  const can = items.filter(e => e.undo && !e.undone && !e.superseded).length;
  const day = iso => new Date(iso).toLocaleDateString(LOC, {day: "numeric", month: "long", year: "numeric"});
  const groups = {};
  for (const e of items) (groups[e.t.slice(0, 10)] ||= []).push(e);
  const row = e => {
    const st = e.undone ? ["clean", "✓", `Отменено ${esc(ago(e.undone))}`] : e.superseded ? ["pending", "·", "Позже это меняли ещё раз — отменять нужно последнее изменение"]
      : e.undo ? ["running", "↺", ""] : ["pending", "i", ""];
    const list = e.items?.length ? `${e.items.slice(0, 4).map(esc).join(" · ")}${e.items.length > 4 ? ` · и ещё ${e.items.length - 4}` : ""}` : "";
    return `<div class="check chg${e.undone ? " done" : ""}"><span class="ic ic-${st[0]}">${st[1]}</span>
      <span><b>${esc(e.title)}</b>${list ? `<span class="sub">${list}</span>` : ""}${st[2] ? `<span class="sub">${st[2]}</span>` : ""}${!e.undo && e.how ? `<span class="sub">${esc(e.how)}</span>` : ""}</span>
      <span class="acts"><span class="sub">${esc(e.t.slice(11, 16))}</span>${e.undo && !e.undone && !e.superseded ? `<button class="small" data-change-undo="${esc(e.id)}" data-title="${esc(e.title)}">Отменить</button>` : ""}</span></div>`;
  };
  return pnl(`${head("Что изменил ScanHub", items.length ? `изменений: ${items.length} · можно отменить: ${can}` : "", `<button data-task-run="changes">Обновить</button>`)}
    ${explain("Всё, что ScanHub менял на компьютере по твоим нажатиям: настройки приватности и защиты, автозагрузка, меню правой кнопки, брандмауэр, PATH, удалённые записи программ и ярлыки, отключённые драйверы. «Отменить» возвращает как было — ScanHub сохранял исходное состояние перед каждым изменением. Удалённые файлы (мусор, кэши, старые драйверы) вернуть нельзя — у таких пунктов так и написано.")}
    ${taskBusy("changes", "Читаю журнал…")}${taskErr("changes")}${taskBusy("change_undo", "Возвращаю как было…")}${taskErr("change_undo")}
    ${items.length ? Object.entries(groups).map(([d, list]) => `<div class="grp">${esc(day(list[0].t))}</div><div class="checks">${list.map(row).join("")}</div>`).join("")
      : t?.status === "done" ? `<div class="note info">ScanHub пока ничего не менял на этом компьютере. Записи появятся здесь, когда ты применишь настройки, удалишь записи программ, выключишь что-то из автозагрузки и т. п.</div>` : ""}`);
}
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-change-undo]");
  if (!b) return;
  if (!await ask(`Отменить «${b.dataset.title}»? ScanHub вернёт исходное состояние. Для системных настроек появится окно UAC (в нём будет «Python» — это ScanHub).`)) return;
  await runTask("change_undo", {id: b.dataset.changeUndo});
  runTask("changes", undefined, true);
});
function afterTask(name, args, t){
  const r = t?.result;
  const again = n => runTask(n, undefined, true);
  if (name === "hosts_set") again("hosts");
  if (name === "watch_set") again("watch");
  if (name === "junk_clean") again("junk_scan");
  if (name === "empty_remove" && TASK.empty?.args?.path) runTask("empty", {path: TASK.empty.args.path}, true);
  if (name === "shortcuts_remove") again("shortcuts");
  if (name === "envpath_fix") again("envpath");
  if (name === "drvstore_remove") again("drvstore");
  if (["uninstall", "force_remove"].includes(name)) { delete TASK.leftovers_remove; again("programs") }
  if (name === "force_remove" && t?.status === "done" && TASK.winget?.result?.apps?.some(a => a.ghost?.key === args?.key)) {
    TASK.winget.result.apps = TASK.winget.result.apps.filter(a => a.ghost?.key !== args.key);   // запись убрана — из обновлений тоже
    if (r?.leftovers?.length) go("apps", "uninst");             // остатки показываются там — отметить и удалить
    else redrawPanels();
  }
  if (name === "force_remove_many" && t?.status === "done" && TASK.winget?.result?.apps) {
    const gone = new Set(args?.keys || []);
    TASK.winget.result.apps = TASK.winget.result.apps.filter(a => !(a.ghost && gone.has(a.ghost.key) && !(r?.failed || []).includes(a.ghost.name)));
    again("programs"); redrawPanels();
  }
  if (name === "leftovers_remove") again("programs");
  if (name === "prepare") refresh();
  if (name === "appx_remove") again("appx");
  if (["privacy_apply", "privacy_revert"].includes(name) && r?.items) TASK.privacy = {status: "done", result: r.items, finished: t.finished};
  if (["security_apply", "security_revert"].includes(name) && r?.items) TASK.security = {status: "done", result: r.items, finished: t.finished};
  if (name === "ctx_set") again("ctx");
  if (["game_on", "game_off"].includes(name) && r) TASK.game = {status: "done", result: r, finished: t.finished};
  if (name === "firewall_set") again("firewall");
  if (name === "startup_set") again("startup");
  if (name === "boot_trace") again("startup");
  if (["restore_create", "restore_enable"].includes(name)) again("restore");
  if (["quarantine", "q_restore", "q_delete"].includes(name) && r?.items) TASK.quarantine_list = {status: "done", result: {items: r.items}};
  if (name === "recycle" && r) {
    const gone = new Set(args.paths || []);
    for (const p of args.paths || []) for (const s of Object.values(SEL)) s.delete(p);
    const d = TASK.disk_analyze?.result; if (d) d.big = d.big.filter(f => !gone.has(f.path));
    const u = TASK.dups?.result; if (u) u.groups = u.groups.map(g => ({...g, paths: g.paths.filter(p => !gone.has(p))})).filter(g => g.paths.length > 1);
  }
  if (name === "quarantine") { ultraForget(args.files); for (const j of openJobs) if (j.found) j.found = j.found.filter(f => !(args.files || []).some(x => x.path === f.path)); renderSimpleResult() }
  redrawPanels(); renderNav();
  if (PAGE === "home") renderTodo();
}

document.addEventListener("click", async e => {
  const el = e.target.closest("[data-upd-go],[data-upd-skip],[data-upd-hide],[data-upd-force],[data-upd-all]");
  if (!el) return;
  if (el.hasAttribute("data-upd-go")) {
    const ids = [...(SEL.upd || [])];
    if (!ids.length) return;
    if (!await ask(`Обновить выбранные программы (${ids.length})? ScanHub скачает установщики, проверит их на вирусы и поставит тихо. ` +
                 "Программы «для всех пользователей» попросят одно окно UAC на все сразу. Открытые программы лучше закрыть.")) return;
    return startUpdates(ids).then(redrawPanels);
  }
  if (el.hasAttribute("data-upd-skip")) return api("/api/updates/skip", {id: UPD.id}).then(() => toast("Пропускаю текущую программу", "", "info"));
  if (el.hasAttribute("data-upd-hide")) { UPD = {id: null, data: null, polling: false}; store.set("upd", ""); return redrawPanels() }
  if (el.dataset.updForce) { if (el.dataset.confirm && !await ask(el.dataset.confirm)) return; return startUpdates([el.dataset.updForce], true).then(redrawPanels) }
  if (el.dataset.updAll) {
    const apps = (TASK.winget?.result?.apps || []).filter(a => !a.ghost);
    SEL.upd = new Set(el.dataset.updAll === "1" ? apps.map(a => a.id) : []);
    return redrawPanels();
  }
});

// ---------- строки сканеров в итоге проверки открывают подробности
document.addEventListener("click", e => { const li = e.target.closest("li[data-det]"); if (li) showDetails(li.dataset.det) });
document.addEventListener("keydown", e => { const li = e.target.closest?.("li[data-det]"); if (li && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); showDetails(li.dataset.det) } });

// ============================================================ перетаскивание файлов в окно
const dropZone = document.createElement("div");
dropZone.id = "dropZone";
dropZone.innerHTML = `<div class="dz-card"><div class="dz-ic">⤓</div><b>Отпусти — проверю на вирусы</b><span>файл, несколько файлов или папку</span></div>`;
document.body.appendChild(dropZone);
let dragDepth = 0;
const hasFiles = e => [...(e.dataTransfer?.types || [])].includes("Files");
addEventListener("dragenter", e => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; dropZone.classList.add("on") });
addEventListener("dragover", e => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy" });
addEventListener("dragleave", e => { if (!hasFiles(e)) return; if (--dragDepth <= 0) { dragDepth = 0; dropZone.classList.remove("on") } });
addEventListener("drop", e => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth = 0; dropZone.classList.remove("on"); dropScan(e.dataTransfer) });

async function dropUpload(id, file){
  const r = await fetch(`/api/drop/upload?id=${id}&name=${encodeURIComponent(file.name)}`,
                        {method: "POST", headers: {"X-Token": TOKEN, "Content-Type": "application/octet-stream"}, body: file});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j.path;
}
async function dropScan(dt){
  const ents = [...dt.items].filter(i => i.kind === "file").map(i => ({file: i.getAsFile(), dir: !!i.webkitGetAsEntry?.()?.isDirectory})).filter(x => x.file);
  if (!ents.length) return;
  const tools = TOOLS.filter(t => t.ready && !t.data_missing && t.modes.some(m => m.multi));
  if (!tools.length) return say("Сначала установи хотя бы один сканер — в разделе «Сканеры» или «Проверка на вирусы».", "Нечем проверять");
  if (ents.some(x => x.dir) && ents.length > 1) return say("Перетащи папку отдельно от других файлов — или выбери её кнопкой «Проверить папку».", "Папку — по одной");
  let paths;
  try { paths = (await api("/api/drop/locate", {files: ents.map(x => ({name: x.file.name, size: x.file.size, mtime: x.file.lastModified, dir: x.dir}))})).paths }
  catch (e) { return toast("Не получилось", e.message, "err") }
  let target, note = "";
  const label = ents.length > 1 ? `файлов: ${ents.length}` : ents[0].file.name;
  if (ents.length === 1 && paths[0]) target = paths[0];
  else if (ents[0].dir) return say(`Не нашёл папку «${ents[0].file.name}» на диске. Выбери её кнопкой «Проверить папку» — так ScanHub получит точный путь.`, "Не удалось найти папку");
  else {
    const id = Math.random().toString(36).slice(2, 12).padEnd(8, "0");
    const miss = ents.filter((x, i) => !paths[i]);
    if (miss.length) toast(`Копирую в ScanHub: ${miss.length === 1 ? miss[0].file.name : "файлов " + miss.length}`, "файл перетащили не из папки — проверю его копию", "info");
    try {
      const up = [];
      for (const x of miss) up.push(await dropUpload(id, x.file));
      target = ents.length === 1 ? up[0] : (await api("/api/drop/collect", {id, paths: paths.filter(Boolean)})).path;
    } catch (e) { return say(e.message, "Файл не удалось проверить") }
    note = ents.length === 1 ? "Файл перетащили не из папки (например, из браузера или архива), поэтому проверялась его копия. Если что-то найдено — удали и оригинал."
         : "Файлы скопированы в одну папку ScanHub и проверены целиком. Если что-то найдено — удали и оригиналы.";
  }
  const batch = await scanBatch(target, tools, {kind: ents.length === 1 && !ents[0].dir ? "file" : "folder", dropped: note, label});
  simpleBatch = batch;
  if (PAGE !== "scan" || SUB !== "check") go("scan", "check");
  renderSimpleResult();
  $("#sResult")?.scrollIntoView({block: "start", behavior: "smooth"});
}

// ============================================================ клики и переключатели новых разделов
document.addEventListener("click", async e => {
  const el = e.target.closest("[data-stop-batch],[data-go],[data-tab-go],[data-go-page],[data-act],[data-dir],[data-pick-run],[data-sel-run],[data-quar],[data-shred-add],[data-shred-clear],[data-shred-go],[data-game-on],[data-dups-go],[data-dups-drive],[data-left-go],[data-left-skip],[data-left-delay],[data-why-protected],[data-task-cancel],[data-junk-go],#burger");
  if (!el) return;
  if (el.id === "burger") return document.body.classList.toggle("nav-open");
  if (el.dataset.stopBatch) {
    const b = batches[el.dataset.stopBatch];
    for (const id of b?.jobs || []) { const j = openJobs.find(x => x.id === id); if (j?.status === "running") api("/api/stop", {id}).catch(() => {}) }
    return toast("Проверка остановлена", "", "info");
  }
  if (el.dataset.go) { e.preventDefault(); return go(el.dataset.go) }
  if (el.dataset.tabGo) return go(PAGE, el.dataset.tabGo);
  if (el.dataset.goPage) {
    const mb = el.closest(".mdl-back");                     // ссылка внутри окна подтверждения — окно закрыть (как «Отмена», не «Да»)
    (mb?.querySelector("[data-mdl='0']") || mb?.querySelector("[data-mdl='1']"))?.click();
    const [p, s] = el.dataset.goPage.split(":"); return go(p, s);
  }
  if (el.dataset.act) {
    if (el.dataset.act === "file" || el.dataset.act === "folder") { go("scan", "check"); return simpleScan(el.dataset.act) }
    if (el.dataset.act === "pick") return modal({title: "Что проверить?", icon: "?", wide: false, buttons: false,
      body: "Все сканеры сразу, в конце — общий итог: можно ли запускать.",
      html: `<div class="pick2">
        <button class="pick" data-mdl="0" data-act="file">${icon("file")}<b>Файл</b><span>скачанная программа, установщик, документ</span></button>
        <button class="pick" data-mdl="0" data-act="folder">${icon("folder")}<b>Папку</b><span>«Загрузки», флешка, папка игры</span></button></div>
        <div class="sub" style="text-align:center">Или просто перетащи файл в окно ScanHub. <a data-mdl="0">Отмена</a></div>`});
    if (el.dataset.act === "quick") { go("scan", "check"); return $("#sQuick").click() }
  }
  if (el.dataset.dir) {
    try { DISK_VIEW = await api(`/api/disk?path=${encodeURIComponent(el.dataset.dir)}`); redrawPanels() }
    catch (err) { toast("Не получилось открыть папку", err.message, "err") }
    return;
  }
  if (el.dataset.pickRun) {
    const r = await api("/api/pick", {kind: "folder"});
    if (!r.path) return;
    const name = el.dataset.pickRun, args = {path: r.path};
    if (name === "dups") args.min_mb = +($("#dupMin")?.value || 1);
    if (name === "disk_analyze") DISK_VIEW = null;
    return runTask(name, args).then(t => afterTask(name, args, t));
  }
  if (el.dataset.dupsDrive) {
    if (!await ask(`Искать дубликаты на всём диске ${el.dataset.dupsDrive}? Это может занять несколько минут.`)) return;
    return runTask("dups", {path: el.dataset.dupsDrive, min_mb: +($("#dupMin")?.value || 1)});
  }
  if (el.dataset.selRun) {
    const name = el.dataset.selRun, S = SEL[el.dataset.selName] || new Set();
    if (!S.size) return toast("Ничего не отмечено", "", "info");
    if (el.dataset.confirm && !await ask(el.dataset.confirm)) return;
    let vals = [...S];
    if (name === "envpath_fix") vals = vals.map(v => { const [scope, ...rest] = v.split("|"); return {scope, entry: rest.join("|")} });
    const args = {[el.dataset.selArg]: vals};
    if (el.hasAttribute("data-rp")) args.restore_point = rpOn();
    const t = await runTask(name, args);
    return afterTask(name, args, t);
  }
  if (el.dataset.dupsGo) {
    const S = SEL.dups || new Set(), r = TASK.dups?.result;
    if (!S.size) return toast("Ничего не отмечено", "", "info");
    if (r?.groups.some(g => g.paths.every(p => S.has(p)))) return say("В одной из групп отмечены все копии — оставь хотя бы один файл в каждой группе.");
    if (!await ask(`Отправить в Корзину отмеченные копии (${S.size})?`)) return;
    const args = {paths: [...S]}, t = await runTask("recycle", args);
    return afterTask("recycle", args, t);
  }
  if (el.dataset.leftGo) {
    const t = TASK[el.dataset.leftGo]?.result, S = SEL.left || new Set();
    const items = (t?.leftovers || []).filter(i => S.has(i.path));
    if (!items.length) return toast("Ничего не отмечено", "", "info");
    if (!await ask(`Удалить отмеченные остатки (${items.length})? ` + (items.some(i => i.kind === "service") ? "Службы будут остановлены и удалены. " : "") +
                   "Папки уйдут в Корзину, ключи реестра сохранятся в резервную копию.")) return;
    const args = {items, restore_point: rpOn()}, r = await runTask("leftovers_remove", args);
    // сервер сам перепроверяет, что осталось: удалённое исчезает, неудалённое остаётся с причиной
    if (t && r.result?.left) {
      const left = new Map(r.result.left.map(i => [i.path, i]));
      t.leftovers = t.leftovers.filter(i => !S.has(i.path) || left.has(i.path)).map(i => left.get(i.path) || i);
      SEL.left = new Set(r.result.left.map(i => i.path));
    }
    return afterTask("leftovers_remove", args, r);
  }
  if (el.dataset.leftDelay) {
    const t = TASK[el.dataset.leftDelay]?.result;
    const items = (t?.leftovers || []).filter(i => i.why && i.kind === "folder");
    if (!items.length || !await ask(`Удалить занятые папки (${items.length}) при следующей перезагрузке? Windows удалит их, пока программы ещё не запущены. ` +
                                    "Попросит права администратора.", {ok: "Удалить при перезагрузке"})) return;
    const r = await runTask("leftovers_delay", {items});
    if (r.status === "done" && t) t.leftovers = t.leftovers.map(i => items.includes(i) ? {...i, why: "удалится при перезагрузке"} : i);
    return redrawPanels();
  }
  if (el.dataset.taskCancel) { await api("/api/task/cancel", {name: el.dataset.taskCancel}); if (TASK[el.dataset.taskCancel]) TASK[el.dataset.taskCancel].cancel = true; toast("Перестаю ждать", el.dataset.taskCancel === "prepare" ? "закончу текущий шаг и остановлюсь" : "проверяю, удалилась ли программа", "info"); return redrawPanels() }
  if (el.hasAttribute("data-junk-go")) {
    const r = TASK.junk_scan?.result, S = SEL.junk || new Set();
    if (!r || !S.size) return toast("Ничего не отмечено", "", "info");
    const cats = r.categories.filter(c => S.has(c.id)), total = cats.reduce((a, c) => a + (c.size || 0), 0) + (S.has("recycle") ? r.recycle.size : 0);
    const admin = cats.some(c => c.admin);
    if (!await ask(`Очистить выбранное (${fmtB(total)})?` + (S.has("recycle") ? " Корзина очистится навсегда — вернуть файлы будет нельзя." : "") +
                   (admin ? " Для системных папок Windows попросит права администратора." : ""),
                   {ok: "Очистить", danger: S.has("recycle")})) return;
    const args = {ids: [...S]}, t = await runTask("junk_clean", args);
    return afterTask("junk_clean", args, t);
  }
  if (el.dataset.whyProtected) return say(el.dataset.whyProtected, el.dataset.whyName + " не удаляется");
  if (el.dataset.leftSkip) { const t = TASK[el.dataset.leftSkip]?.result; if (t) t.leftovers_done = true; return redrawPanels() }
  if (el.dataset.quar) {
    const files = JSON.parse(el.dataset.quar);
    if (!await ask(files.length > 1 ? `Убрать в карантин ${files.length} файлов? Они перестанут запускаться; вернуть можно в «Проверка на вирусы → Карантин».`
                                  : `Убрать в карантин ${files[0].path.split("\\").pop()}? Файл перестанет запускаться; вернуть можно в «Карантине».`)) return;
    const args = {files}, t = await runTask("quarantine", args);
    return afterTask("quarantine", args, t);
  }
  if (el.dataset.shredAdd) {
    const r = await api("/api/pick", {kind: el.dataset.shredAdd});
    if (r.path && !SHRED.includes(r.path)) { SHRED.push(r.path); runTask("media", {path: r.path}, true) }
    return redrawPanels();
  }
  if (el.hasAttribute("data-shred-clear")) { SHRED = []; return redrawPanels() }
  if (el.hasAttribute("data-shred-go")) {
    if (!await ask(`Уничтожить безвозвратно ${SHRED.length} объектов? Восстановить их будет невозможно, даже программами восстановления.`)) return;
    if (!await ask("Точно? Это последнее предупреждение: файлы исчезнут навсегда.", {danger: true, ok: "Уничтожить"})) return;
    const args = {paths: SHRED.slice()};
    const t = await runTask("shred", args);
    if (t.status === "done") SHRED = [];
    return redrawPanels();
  }
  if (el.hasAttribute("data-game-on")) {
    const opts = [...(SEL.game || [])];
    const t = await runTask("game_on", {opts});
    return afterTask("game_on", {opts}, t);
  }
});
document.addEventListener("change", async e => {
  const x = e.target;
  if (x.dataset.sel) {
    const S = SEL[x.dataset.sel] ||= new Set();
    x.checked ? S.add(x.value) : S.delete(x.value);
    if (["junk", "appx", "drv", "dups", "priv", "upd"].includes(x.dataset.sel)) redrawPanels();
    return;
  }
  if (x.id === "rpOn") { store.set("rp", x.checked ? "1" : "0"); return redrawPanels() }
  if (x.id === "appxKeep") { store.set("appxkeep", x.checked ? "1" : "0"); return redrawPanels() }
  if (x.id === "brAll") { store.set("brall", x.checked ? "1" : "0"); return redrawPanels() }
  if (x.id === "dupMin") return store.set("dupmin", x.value);
  if (x.id === "diagDays") { store.set("diagdays", x.value); return runTask("diag", {days: +x.value}) }
  if (x.hasAttribute("data-alerts-on")) {
    await api("/api/config", {alerts_on: x.checked});
    toast(x.checked ? "Предупреждения включены" : "Предупреждения выключены", "", "info");
    await pollAlerts(); return redrawPanels();
  }
  if (x.dataset.startup) {
    const args = {id: x.dataset.startup, enable: x.checked};
    const t = await runTask("startup_set", args);
    if (t.status === "error") x.checked = !x.checked;
    return afterTask("startup_set", args, t);
  }
  if (x.dataset.ctx) {
    const args = {id: x.dataset.ctx, enable: x.checked, restore_point: rpOn() && !x.dataset.ctx.startsWith("classic")};
    const t = await runTask("ctx_set", args);
    afterTask("ctx_set", args, t);
    if (t.status === "done" && await ask("Перезапустить Проводник сейчас, чтобы увидеть изменения? Открытые окна папок закроются.")) runTask("explorer_restart");
    return;
  }
  if (x.dataset.fw) {
    const args = {ids: JSON.parse(x.dataset.fw), enable: x.checked};
    const t = await runTask("firewall_set", args);
    return afterTask("firewall_set", args, t);
  }
});

// ============================================================ старт
render();
refresh();
go(PAGE, SUBS[PAGE]);
setInterval(refresh, 4000);
pollAlerts();
setInterval(() => api("/api/ping", {}).catch(() => {}), 20000);
api("/api/jobs").then(r => {
  r.jobs.filter(j => j.tool !== "ultra" && !j.parent).forEach(j => follow(j.id, true));
  const u = r.jobs.find(j => j.tool === "updates");
  if (u) { UPD.id = u.id; store.set("upd", u.id) }
  if (UPD.id) pollUpd();
});
loadUltra();
api("/api/config").then(c => { CFG = c; const ev = $("#every"); if (ev) ev.textContent = c.check_every_hours });

// ---------- «Понятно» у советов на главной
document.addEventListener("click", e => {
  const a = e.target.closest("[data-todo-ack],[data-todo-unack]");
  if (!a) return;
  const set = todoAck();
  if (a.hasAttribute("data-todo-unack")) set.clear(); else set.add(a.dataset.todoAck);
  store.set("todo.ack", JSON.stringify([...set]));
  renderTodo(); renderNav();
});

// ---------- «Сбои и ошибки»: подробности строки и «Решить» у вылета
document.addEventListener("click", async e => {
  const fix = e.target.closest("[data-crash-fix]");
  if (fix) {
    e.preventDefault(); e.stopPropagation();
    const a = JSON.parse(fix.dataset.crashFix);
    document.querySelector(".mdl-back")?.querySelector("[data-mdl='0']")?.click();
    toast("Ищу, что можно сделать…", a.app, "info", 2500);
    let r;
    try { const t = await runTask("crash_fix", {app: a.app, path: a.path}, true); if (t.status !== "done") throw new Error(t.error || "не получилось"); r = t.result }
    catch (err) { return toast("Не получилось", err.message, "bad") }
    const opt = (o, i) => `<div class="fixopt"><div><b>${esc(o.label)}</b><div class="sub">${esc(o.desc)}</div></div>
      ${o.kind === "info" ? "" : `<button class="small ${i === 0 ? "primary" : ""}" data-fixopt="${i}">${esc(o.kind === "update" ? "Обновить" : o.kind === "go" ? "Открыть" : o.label)}</button>`}</div>`;
    const html = `${r.program ? `<div class="sub">Программа: <b>${esc(r.program)}</b>${r.version ? " " + esc(r.version) : ""}</div>` : ""}
      ${a.count === 1 ? `<div class="note info">Вылет был один раз — скорее всего, случайность. Делать что-то стоит, если повторится.</div>` : ""}
      ${(r.options || []).map(opt).join("")}${r.note ? `<div class="note info">${esc(r.note)}</div>` : ""}
      <div class="row-tools">${aiBtn(`Вылеты ${a.app}`, `Программа вылетает. Путь: ${a.path}. ${r.program ? "Это " + r.program + "." : ""}`, {source: "Сбои и ошибки · Решить"})}</div>`;
    const wrapP = modal({title: `Как исправить вылеты ${a.app}`, html, ok: "Закрыть", cancel: null, icon: "!", wide: true});
    setTimeout(() => document.querySelectorAll("[data-fixopt]").forEach(b => b.onclick = async () => {
      const o = r.options[+b.dataset.fixopt];
      document.querySelector(".mdl-back [data-mdl='1']")?.click();
      if (o.kind === "update") { try { await api("/api/updates", {ids: o.ids}); go("apps", "updates"); toast("Обновление запущено", "ScanHub проверит установщик на вирусы и поставит") } catch (err) { toast("Не получилось", err.message, "bad") } }
      else if (o.kind === "go") { const [p, sub] = o.page.split(":"); go(p, sub) }
      else if (o.kind === "launch") api("/api/launch", {what: o.what}).catch(err => toast("Не удалось открыть", err.message, "bad"));
    }), 50);
    await wrapP;
    return;
  }
  const row = e.target.closest("[data-diag-det]");
  if (!row || e.target.closest("button,a,select,input")) return;
  const d = DIAG_DET[+row.dataset.diagDet];
  if (d) modal({title: d.title, html: d.html, ok: "Закрыть", cancel: null, icon: "i", wide: true});
});

// ============================================================ СКОРОСТЬ → ИНТЕРНЕТ: «почему тормозит интернет»
function pNet(dev){
  const t = TASK.net_diag, r = t?.result, running = t?.status === "running";
  const right = `<button class="${r ? "" : "primary"}" data-task-run="net_diag" ${running ? "disabled" : ""}>${r ? "Проверить снова" : "Проверить интернет"}</button>`;
  const intro = explain("ScanHub проверит по очереди: сигнал Wi‑Fi, связь с роутером, связь с интернетом, скорость DNS и скорость скачивания и отдачи. Так видно, где именно тормозит: в компьютере, в Wi‑Fi или роутере, в DNS или у провайдера. Около 40 секунд; на замер скорости уйдёт около 60 МБ трафика (тест Cloudflare). Ничего не меняется.");
  if (!r) return pnl(head("Почему тормозит интернет", "", right) + intro + busyErr("net_diag", `Проверяю… ${esc(t?.progress || "")}`));
  const ic = {ok: ["clean", "✓"], info: ["running", "i"], warn: ["suspicious", "!"], bad: ["threat", "!"]};
  const g = r.gateway || {}, n = (r.internet || [])[0] || {}, w = r.wifi;
  const tile = (label, val, sub = "") => `<div class="kpi"><span class="sub">${esc(label)}</span><b>${val}</b>${sub ? `<span class="sub">${esc(sub)}</span>` : ""}</div>`;
  const ms = v => v == null ? "—" : `${v} мс`;
  return pnl(`${head("Почему тормозит интернет", `проверено ${esc(ago(r.when))}`, right)}${busyErr("net_diag", `Проверяю… ${esc(t?.progress || "")}`)}
    <div class="note ${/в порядке/.test(r.verdict) ? "ok-note" : "warn"}"><b>${esc(r.verdict)}</b></div>
    <div class="kpis">${tile("Скачивание", r.down?.mbps != null ? `${r.down.mbps} Мбит/с` : "—")}${tile("Отдача", r.up?.mbps != null ? `${r.up.mbps} Мбит/с` : "—")}
      ${tile("До роутера", ms(g.avg), g.loss_pct != null ? `потери ${g.loss_pct}%` : "")}${tile("До интернета", ms(n.avg), n.loss_pct != null ? `потери ${n.loss_pct}% · разброс ${n.jitter ?? "—"} мс` : "")}
      ${w ? tile("Сигнал Wi‑Fi", w.signal != null ? `${w.signal}%` : "—", [w.band, w.radio].filter(Boolean).join(" · ")) : tile("Подключение", esc(r.adapter?.media === "802.3" ? "кабель" : "—"), r.adapter?.speed || "")}</div>
    <div class="checks">${(r.findings || []).map(f => `<div class="check"><span class="ic ic-${ic[f.lvl]?.[0] || "running"}">${ic[f.lvl]?.[1] || "i"}</span>
      <span><b>${esc(f.t)}</b>${f.s ? `<span class="sub">${esc(f.s)}</span>` : ""}</span><span class="acts">${f.lvl === "ok" ? "" : aiBtn(f.t, f.s, {source: "Скорость · Интернет"})}</span></div>`).join("")}</div>
    ${dev ? `<div class="sub mono">адаптер: ${esc(r.adapter?.desc || "")} · шлюз ${esc(r.adapter?.gateway || "")} · DNS ${esc((r.adapter?.dns || []).join(", "))}</div>` : ""}`);
}
