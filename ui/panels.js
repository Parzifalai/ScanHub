// ============================================================ СИСТЕМА: панели
let DEEP = {id: store.get("deep"), data: null};
const TASK = {};                              // имя -> последнее состояние задачи
const fmtSize = b => b == null ? "—" : fmtB(b);
const ICON = {clean: "✓", threat: "!", suspicious: "?", error: "!", skipped: "–", pending: "", running: '<div class="spin"></div>', unknown: "✓"};

async function runTask(name, args, quiet){
  TASK[name] = await api("/api/task", {name, args});
  redrawPanels(); drawRes();
  while (TASK[name].status === "running") {
    await new Promise(r => setTimeout(r, 1500));
    TASK[name] = await api(`/api/task?name=${name}`);
  }
  redrawPanels(); drawRes();
  if (!quiet) taskToast(name, TASK[name], args || {});
  return TASK[name];
}
async function ensureTask(name){
  if (TASK[name]?.result || TASK[name]?.status === "running") return;
  const t = await api(`/api/task?name=${name}`);
  if (t.status === "none") return runTask(name, undefined, true);
  TASK[name] = t;
  if (t.status === "running") return runTask(name, undefined, true);
  redrawPanels();
}
const taskBusy = (name, text) => {
  const t = TASK[name];
  if (t?.status !== "running") return "";
  const p = progOf(t.progress);
  return `<div class="sub busy" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><div class="spin" style="width:16px;height:16px;border-width:2px"></div>${text}${p.t ? ` <span class="mono">· ${esc(p.t)}</span>` : ""}</div>${progHtml(t.progress, t.started)}`;
};
// уязвимый драйвер: чей он и что с ним делать
function drvFix(list){
  const off = TASK.driver_disable?.result?.service, on = TASK.driver_restore?.result?.service;
  return list.map(d => {
    const disabled = (d.start === 4 || off === d.service) && on !== d.service;
    const who = d.program || d.signer || "неизвестной программы";
    return `<div class="drvfix"><b>Что делать с ${esc(d.file)}</b>
      <span class="sub">Это драйвер программы <b>${esc(who)}</b>${d.signer && d.signer !== who ? ` (подписан ${esc(d.signer)})` : ""}${d.dirs?.length ? ` — папка ${esc(d.dirs[0])}` : ""}.
        Сам по себе он не вирус, но в нём есть известная дыра: вирус, если попадёт на компьютер, может через этот драйвер выключить антивирус. Поэтому лучше, чтобы он не работал постоянно.</span>
      <span class="sub">${d.apps?.length ? `Не пользуешься «${esc(d.apps[0])}» — удали программу, драйвер уйдёт вместе с ней.` : "В списке установленных программ её нет — похоже, программу удалили или она переносная, а драйвер остался и загружается при каждом включении."}
        Пользуешься — отключи драйвер, а когда программа понадобится, включи обратно: без драйвера она не увидит диски.</span>
      ${disabled ? `<span class="sub" style="color:var(--ok)">✓ Драйвер отключён. Он ещё в памяти — перезагрузи компьютер, и он перестанет работать.</span>` : ""}
      <div class="row-tools">${disabled
        ? `<button class="small" data-task-run="driver_restore" data-args="${attr({service: d.service})}" data-confirm="Включить драйвер ${esc(d.file)} обратно? Он снова будет загружаться при включении компьютера. Попросит права администратора.">Включить обратно</button>`
        : `<button class="small primary" data-task-run="driver_disable" data-args="${attr({service: d.service})}" data-confirm="Отключить драйвер ${esc(d.file)}? Он перестанет загружаться после перезагрузки, а ${esc(who)} перестанет работать с дисками, пока не включишь его обратно. Попросит права администратора. Исходное состояние сохранится.">Отключить драйвер</button>`}
        ${d.apps?.length ? `<button class="small" data-go-page="apps:uninst">Удалить программу</button>` : ""}
        ${d.dirs?.length ? `<button class="small" data-open="${esc(d.dirs[0])}">Открыть папку программы</button>` : ""}</div></div>`;
  }).join("");
}
const taskErr = name => TASK[name]?.error ? `<div class="note bad">${esc(TASK[name].error)}<a class="bug-link" data-bug="${esc(TASK[name].error)}" title="Если это похоже на ошибку ScanHub, а не на проблему компьютера — напиши автору">Сообщить об ошибке</a></div>` : "";

const head = (title, sub, right = "") => `<div class="head"><div><h3>${title}</h3>${sub ? `<div class="sub">${sub}</div>` : ""}</div><div class="grow"></div>${right}</div>`;

// ---------- глубокая проверка
const DEEP_PLAN = [
  ["Внедрённый код в процессах", "HollowsHunter проверяет все запущенные программы (попросит права администратора один раз)"],
  ["Скрытые майнеры", "нагрузка на процессор и видеокарту, имена, откуда запущены, подписи"],
  ["Сеть", "соединения с майнинг-пулами, подмена файла hosts"],
  ["Автозагрузка", "реестр, папки, задачи, службы, WMI, вход в Windows, перехват запуска программ, экран входа"],
  ["Настройки Defender", "исключения и выключенные защиты — так вредоносы прячутся от антивируса (в том же окне UAC)"],
  ["Браузеры", "расширения не из магазина и с опасными правами, политики, подмена прокси"],
  ["Microsoft Defender", "быстрая проверка памяти и системных мест"],
  ["ClamAV", "Загрузки, Рабочий стол, TEMP, автозагрузка и программы в AppData"],
  ["Правила YARA", "7 тыс. правил Elastic и YARA Forge по тем же файлам"],
  ["Atomdrift Scan", "если установлен"],
  ["Онлайн-сверка", "подозрительные файлы — в VirusTotal и Filescan (только хэши)"],
];
function pDeep(dev){
  const d = DEEP.data;
  const startBtn = `<button class="primary" id="deepStart">${d ? "Проверить ещё раз" : "Начать глубокую проверку"}</button>`;
  if (!d) return `<div class="pnl">${head("Глубокая проверка", "Все сканеры по очереди, в конце — общий итог. Обычно 15–40 минут, можно свернуть окно.", startBtn)}
    <ul class="steps">${DEEP_PLAN.map(([t, h], i) => `<li><span class="ic ic-pending">${i + 1}</span><span class="t"><b>${t}</b><span class="sub">${h}</span></span><span></span></li>`).join("")}</ul>
    ${!tool("clamav")?.ready || tool("clamav")?.data_missing ? `<div class="note info">ClamAV ещё не готов: ${tool("clamav")?.ready ? "скачай базы кнопкой в карточке ClamAV (режим «Разработчик»)" : "установи его в режиме «Разработчик»"}. Без него этот шаг пропустится.</div>` : ""}</div>`;
  const steps = d.steps || [], done = steps.filter(s => s.status === "done" || s.status === "skipped").length;
  const running = d.status === "running", v = d.verdict?.[0];
  const big = running ? `<div class="icon i-run"><div class="spin"></div></div>` :
    `<div class="icon ${v === "threat" ? "i-bad" : v === "suspicious" || v === "error" || d.problems?.length ? "i-warn" : "i-ok"}">${v === "threat" ? "!" : v === "suspicious" ? "?" : v === "error" || d.problems?.length ? "!" : "✓"}</div>`;
  const title = running ? `Идёт глубокая проверка… шаг ${Math.min(done + 1, steps.length)} из ${steps.length}` : esc(d.verdict?.[1] || "Готово");
  const right = running ? `<button class="danger" data-stop-job="${d.id}">Остановить</button>` : startBtn;
  const recs = ["cureit", "kvrt", "eset", "emsisoft", "msert", "malwarebytes", "adwcleaner"].map(tool).filter(Boolean);     // MinerSearch уже внутри глубокой
  const hjt = tool("hijackthis");   // те же, что советует ультра проверка
  return `<div class="pnl">
    <div class="head"><div class="result" style="padding:0;border:0;background:none"><div class="big">${big}<div><h3 style="margin:0">${title}</h3>
      <div class="sub">${running ? "можно свернуть окно — проверка продолжится" : "закончена " + esc((d.finished || "").replace("T", " "))}</div></div></div></div><div class="grow"></div>${right}</div>
    ${running ? progBar(done / steps.length) : problemsHtml(d.problems)}
    <ul class="steps">${steps.map(s => {
      const st = s.status === "done" ? (s.verdict || "clean") : s.status;
      const f = dev ? s.findings : s.findings.slice(0, 5);
      return `<li><span class="ic ic-${st === "unknown" ? "clean" : st}">${ICON[st] ?? ""}</span>
        <span class="t"><b>${esc(s.title)}</b><span class="sub">${esc(s.hint)}</span>
        ${f.length ? `<ul>${f.map(x => `<li>${esc(x)}</li>`).join("")}${s.findings.length > f.length ? `<li class="sub">…и ещё ${s.findings.length - f.length} (подробности — в режиме «Разработчик»)</li>` : ""}</ul>` : ""}${s.problem ? `<span class="sub" style="color:var(--bad);display:block;margin-top:4px">⚠ ${esc(s.problem)}</span>` : ""}${!running && s.files?.length ? qButtons(s.files) : ""}${!running && s.drivers?.length ? drvFix(s.drivers) : ""}${!running && s.files_done ? `<span class="sub" style="color:var(--accent);display:block;margin-top:4px">✓ найденные файлы уже убраны в карантин или удалены</span>` : ""}</span>
        <span class="lbl">${esc(s.status === "pending" ? "ждёт" : s.status === "running" ? "идёт…" : s.label)}${!running && (s.findings.length || s.problem) ? aiBtn(`${s.title}: ${s.label}`, [...s.findings.slice(0, 15), s.problem || ""].join("; "), {source: "Глубокая проверка"}) : ""}</span></li>`;
    }).join("")}</ul>
    ${dev ? `<div><a data-show-deep="${d.id}">Открыть полный лог в консоли</a></div>` : ""}
    ${!running ? recsHtml(recs.map(t => t.id), {threat: v === "threat" || v === "suspicious",
        extra: hjt ? `<div class="rec-g"><div class="rec-gh">Подробный отчёт о системе</div><div class="recs">${hjtTile()}</div></div>` : ""}) : ""}
  </div>`;
}
async function pollDeep(){
  if (!DEEP.id) return;
  try { DEEP.data = await api(`/api/job?id=${DEEP.id}&since=999999`) } catch { DEEP.id = null; DEEP.data = null; store.set("deep", ""); return }
  redrawPanels();
  if (DEEP.data.status === "running") { DEEP.wasRunning = true; setTimeout(pollDeep, 1500) }
  else {
    refresh();
    if (DEEP.wasRunning) {
      DEEP.wasRunning = false;
      const v = DEEP.data.verdict?.[0];
      toast(`Глубокая проверка завершена: ${(DEEP.data.verdict?.[1] || "готово").toLowerCase()}`, "итоги — в панели «Глубокая проверка»", verdictKind(v), 10000);
    }
  }
}

// ---------- полная проверка ПК
function healthChecks(h){
  const C = [], add = (grp, st, title, text = "", action = "") => C.push({grp, st, title, text, action});
  const df = h.defender || {};
  add("Защита", df.realtime ? "ok" : "bad", df.realtime ? "Defender защищает в реальном времени" : "Защита в реальном времени выключена", df.realtime ? "" : "Включи в «Безопасность Windows»", `<button class="small" data-launch="defender">Открыть</button>`);
  add("Защита", (df.sig_age ?? 0) <= 2 ? "ok" : "warn", `Базы Defender: ${df.sig_age ?? "?"} дн.`, (df.sig_age ?? 0) > 2 ? "Обнови базы" : "", (df.sig_age ?? 0) > 2 ? `<button class="small" data-run="defender" data-mode="sigupdate">Обновить</button>` : "");
  const fwOff = (h.firewall || []).filter(f => !f.on).map(f => f.name);
  add("Защита", fwOff.length ? "bad" : "ok", fwOff.length ? `Брандмауэр выключен: ${fwOff.join(", ")}` : "Брандмауэр включён во всех профилях");
  add("Защита", h.uac?.lua === 0 ? "bad" : h.uac?.prompt === 0 ? "warn" : "ok", h.uac?.lua === 0 ? "Контроль учётных записей (UAC) выключен" : h.uac?.prompt === 0 ? "UAC не спрашивает подтверждения" : "UAC включён", h.uac?.lua === 0 ? "Программы получают права администратора без спроса" : "");
  add("Защита", h.secureboot === 1 ? "ok" : "warn", h.secureboot === 1 ? "Secure Boot включён" : "Secure Boot выключен", h.secureboot === 1 ? "" : "Защищает от буткитов. Включается в BIOS/UEFI");
  add("Защита", df.tamper ? "ok" : "warn", df.tamper ? "Защита от подделки включена" : "Защита от подделки выключена", df.tamper ? "" : "Вредонос может отключить Defender. Включи в «Безопасность Windows»");
  const lu = h.last_update ? Math.round((Date.now() - new Date(h.last_update)) / 864e5) : null;
  add("Обновления", lu == null ? "warn" : lu > 45 ? "warn" : "ok", lu == null ? "Не удалось узнать дату обновлений" : `Последнее обновление Windows: ${lu} дн. назад`, lu > 45 ? "Проверь Windows Update" : "", `<button class="small" data-launch="wu">Windows Update</button>`);
  if (h.reboot_pending) add("Обновления", "warn", "Нужна перезагрузка", "Обновления ждут перезагрузки, чтобы установиться");
  for (const v of h.volumes || []) {
    const freePct = 100 - v.percent;
    add("Диски", freePct < 10 ? "bad" : freePct < 20 ? "warn" : "ok", `Диск ${v.mount}: свободно ${fmtB(v.free)} из ${fmtB(v.total)} (${Math.round(freePct)}%)`,
      freePct < 10 ? "Очень мало места — Windows и программы начнут тормозить" : freePct < 20 ? "Места становится мало" : "",
      freePct < 20 ? `<button class="small" data-panel-go="cleanup">Очистка</button>` : "");
  }
  for (const d of h.disks || []) add("Диски", d.health === "Healthy" ? "ok" : "bad", `${d.name} (${d.media}): ${d.health === "Healthy" ? "исправен" : d.health}`, d.health === "Healthy" ? "" : "Срочно сделай резервную копию важных файлов");
  if (h.battery?.design) {
    const wear = Math.max(0, Math.round((1 - h.battery.full / h.battery.design) * 100));
    add("Железо", wear > 40 ? "bad" : wear > 20 ? "warn" : "ok", `Износ батареи: ${wear}%`, `ёмкость ${Math.round(h.battery.full / 1000)} из ${Math.round(h.battery.design / 1000)} Вт·ч${h.battery.cycles ? `, циклов: ${h.battery.cycles}` : ""}`);
  }
  if (M?.gpu?.temp != null) add("Железо", M.gpu.temp > 85 ? "bad" : M.gpu.temp > 75 ? "warn" : "ok", `Температура видеокарты: ${M.gpu.temp}°C`, M.gpu.temp > 80 ? "Почисти систему охлаждения или проверь, что грузит видеокарту" : "");
  add("Система", h.uptime_days > 7 ? "warn" : "ok", `Без перезагрузки: ${h.uptime_days} дн.`, h.uptime_days > 7 ? "Перезагрузи компьютер — освободит память и доставит обновления" : "");
  add("Система", h.ram?.percent > 85 ? "warn" : "ok", `Память занята на ${Math.round(h.ram?.percent ?? 0)}%`, h.ram?.percent > 85 ? "Закрой лишние программы — смотри «Компьютер сейчас»" : "");
  add("Система", h.problem_devices ? "warn" : "ok", h.problem_devices ? `Устройства с ошибками: ${h.problem_devices}` : "Все устройства работают", h.problem_devices ? "Какие именно и что делать — в «Драйверах»" : "", h.problem_devices ? `<button class="small" data-panel-go="drivers">Драйверы</button>` : "");
  if (h.winget == null) add("Программы", "info", "winget не найден — не могу проверить устаревшие программы");
  else add("Программы", h.winget.length > 0 ? "warn" : "ok", h.winget.length ? `Устарели программы: ${h.winget.length}` : "Все программы обновлены",
    h.winget.slice(0, 8).map(a => `${a.name} ${a.version} → ${a.available}`).join(" · ") + (h.winget.length > 8 ? ` · …ещё ${h.winget.length - 8}` : ""),
    h.winget.length ? `<button class="small" data-launch="winget_upgrade">Обновить все</button>` : "");
  return C;
}
function sysfilesChecks(){
  const t = TASK.sysfiles, r = t?.result;
  if (!r || !r.dism) return [];
  const C = [], repair = `<button class="small" data-launch="sfc_repair">Восстановить</button>`;
  if (r.cards) return r.cards.map(c => ({grp: "Системные файлы", st: c.lvl, title: c.title, text: c.text, action: c.action === "repair" ? repair : ""}));
  const D = {ok: ["ok", "Хранилище компонентов Windows исправно", ""],
             repairable: ["bad", "Хранилище компонентов Windows повреждено", "Его можно восстановить: DISM скачает исправные файлы из Windows Update"],
             broken: ["bad", "Хранилище компонентов не восстанавливается автоматически", "Понадобится восстановление с установочного образа Windows"],
             unknown: ["info", "DISM: не удалось разобрать ответ", r.dism_text]}[r.dism];
  C.push({grp: "Системные файлы", st: D[0], title: D[1], text: D[2], action: r.dism === "repairable" ? repair : ""});
  const S = {ok: ["ok", "Системные файлы целы (SFC)", ""],
             violations: ["bad", "Найдены повреждённые системные файлы (SFC)", "Нажми «Восстановить»: сначала DISM, потом SFC починит файлы. Займёт 15–30 минут, затем перезагрузка"],
             busy: ["warn", "SFC не запустился: Windows сейчас устанавливает обновления", "Перезагрузи компьютер и проверь снова"],
             error: ["warn", "SFC не смог выполнить проверку", r.sfc_text],
             unknown: ["info", "SFC: не удалось разобрать ответ", r.sfc_text]}[r.sfc];
  C.push({grp: "Системные файлы", st: S[0], title: S[1], text: S[2], action: r.sfc === "violations" ? repair : ""});
  return C;
}
function pHealth(dev){
  const t = TASK.health, h = t?.result, sf = TASK.sysfiles;
  const running = t?.status === "running" || sf?.status === "running";
  const btn = `<button class="primary" id="healthStart" ${running ? "disabled" : ""}>${h ? "Проверить снова" : "Начать проверку"}</button>`;
  const opt = `<label class="switch" style="align-items:flex-start"><input type="checkbox" id="hSys" ${store.get("hsys") === "1" ? "checked" : ""} ${running ? "disabled" : ""} style="margin-top:3px">
      <span><b>Проверить и системные файлы Windows</b> (DISM + SFC)<span class="sub" style="display:block">ещё 10–15 минут · попросит права администратора · только проверка, ничего не меняет</span></span></label>
    <label class="switch" style="align-items:flex-start"><input type="checkbox" id="hDisk" ${store.get("hdisk") === "1" ? "checked" : ""} ${running ? "disabled" : ""} style="margin-top:3px">
      <span><b>Проверить диски подробно</b> (файловая система, износ и температура SSD, TRIM)<span class="sub" style="display:block">ещё 1–5 минут · то же окно администратора · только проверка</span></span></label>`;
  const sfBusy = taskBusy("sysfiles", "Выполняю проверки с правами администратора… системные файлы — 10–15 минут. Если появится окно UAC — подтверди.") + taskErr("sysfiles");
  if (!h) return `<div class="pnl">${head("Полная проверка ПК", "Защита, обновления, диски, батарея, температура, устройства и устаревшие программы. 1–2 минуты.", btn)}
    ${opt}
    ${taskBusy("health", "Проверяю систему… (обычно минута-две, дольше всего — список устаревших программ)")}${taskErr("health")}${sfBusy}
    <div class="checks">${["Защита: Defender, брандмауэр, UAC, Secure Boot, защита от подделки", "Обновления Windows и ожидающая перезагрузка",
      "Диски: свободное место и исправность", "Батарея: износ и циклы; температура видеокарты", "Время без перезагрузки, память, устройства с ошибками",
      "Устаревшие программы (winget)", "Правила брандмауэра", "По галочкам: целостность системных файлов (DISM + SFC), файловая система, SMART и TRIM дисков"].map(x => `<div class="check"><span class="ic ic-pending">•</span><span>${x}</span><span></span></div>`).join("")}</div></div>`;
  const C = healthChecks(h).concat(sysfilesChecks(), diskChecks(), fwChecks()), bad = C.filter(c => c.st === "bad").length, warn = C.filter(c => c.st === "warn").length;
  const groups = [...new Set(C.map(c => c.grp))];
  const order = {bad: 0, warn: 1, info: 2, ok: 3};
  return `<div class="pnl">${head(bad ? `Нужно исправить: ${bad}` : warn ? `Есть замечания: ${warn}` : "Всё в порядке", `проверено ${esc((t.finished || "").replace("T", " "))} · ${C.length} пунктов`, btn)}
    ${opt}
    ${taskBusy("health", "Проверяю…")}${sfBusy}
    ${groups.map(g => `<div class="grp">${g}</div><div class="checks">${C.filter(c => c.grp === g).sort((a, b) => order[a.st] - order[b.st]).map(c =>
      `<div class="check"><span class="ic ic-${c.st === "ok" ? "clean" : c.st === "bad" ? "threat" : c.st === "warn" ? "suspicious" : "pending"}">${c.st === "ok" ? "✓" : c.st === "info" ? "i" : "!"}</span>
       <span><b>${esc(c.title)}</b>${c.text ? `<span class="sub">${esc(c.text)}</span>` : ""}</span><span>${c.action}</span></div>`).join("")}</div>`).join("")}
  </div>`;
}

// ---------- драйверы
const CM_ERR = {1: "неправильно настроено — переустанови драйвер", 3: "драйвер повреждён или не хватает памяти", 10: "не запускается — обнови драйвер",
  14: "нужна перезагрузка компьютера (часто после обновления прошивки)", 18: "переустанови драйвер", 19: "ошибка в реестре — переустанови драйвер",
  21: "Windows удаляет устройство — перезагрузи", 22: "устройство отключено вручную", 24: "устройство не найдено или драйвер не установлен",
  28: "драйвер не установлен", 31: "работает неправильно — обнови драйвер", 32: "служба драйвера отключена", 39: "драйвер повреждён или отсутствует",
  43: "Windows остановила устройство из-за сбоя — обнови драйвер или проверь железо", 45: "устройство не подключено", 52: "драйвер не прошёл проверку подписи"};
// без совета «обнови драйвер» — для устройств со встроенным драйвером Windows (мыши, клавиатуры, USB)
const CM_SHORT = {10: "не запускается", 31: "работает неправильно", 43: "Windows остановила устройство из-за сбоя"};
// у одной мыши или клавиатуры бывает несколько «интерфейсов» — одинаковые строки показываем одной
function devGroups(list){
  const g = {};
  for (const p of list) (g[(p.Shown || p.Name) + "|" + p.ConfigManagerErrorCode] ||= {...p, n: 0}).n++;
  return Object.values(g);
}
function pDrivers(dev){
  const d = TASK.drivers?.result, u = TASK.driver_updates;
  const btn = `<button class="primary" data-task-run="driver_updates" ${u?.status === "running" ? "disabled" : ""}>Найти обновления драйверов</button>`;
  const old = (d?.drivers || []).filter(x => x.Date && (Date.now() - new Date(x.Date)) / 864e5 > 3 * 365);
  const lenovo = /lenovo/i.test(d?.maker || "");
  return `<div class="pnl">${head("Драйверы", d ? `${esc(d.maker || "")} ${esc(d.family || d.model || "")} · BIOS ${esc(d.bios || "?")} от ${esc(d.bios_date || "?")}` : "", btn)}
    ${taskBusy("drivers", "Собираю список устройств…")}${taskErr("drivers")}
    ${taskBusy("driver_updates", "Ищу драйверы в Windows Update… обычно 30–120 секунд")}${taskErr("driver_updates")}
    ${u?.result ? (u.result.length ? `<div class="note warn"><b>Windows Update нашёл драйверы: ${u.result.length}</b><br>${u.result.map(x => `• ${esc(x.title)}${x.date ? ` (${esc(x.date)})` : ""}`).join("<br>")}
        <div style="margin-top:8px"><button class="small" data-launch="wu_optional">Установить в Windows Update</button></div></div>`
      : `<div class="note info">Windows Update: новых драйверов нет.</div>`) : ""}
    <div class="row-tools">
      <button data-launch="wu_optional">Windows Update → необязательные обновления</button>
      ${d?.nvidia ? `<button data-link="https://www.nvidia.com/ru-ru/geforce/drivers/">NVIDIA: проверить драйвер (сейчас ${esc(d.nvidia.version)})</button>` : ""}
      ${lenovo ? `<button data-link="https://pcsupport.lenovo.com/">Драйверы Lenovo для твоей модели</button>` : ""}
    </div>
    ${d?.pending?.length ? `<div class="note info"><b>Ждут перезагрузки: ${d.pending.length}</b><br>${d.pending.map(p => `• ${esc(p.Name || "Неизвестное устройство")} — Windows поставит обновление при следующей перезагрузке. Если оно так и висит, смотри «Комплектующие»: там видно, почему не ставится прошивка.`).join("<br>")}</div>` : ""}
    ${d?.problems?.length ? `<div class="note bad"><b>Устройства с ошибками: ${d.problems.length}</b><br>${devGroups(d.problems).map(p => `• ${esc(p.Shown || p.Name || "Неизвестное устройство")}${p.n > 1 ? ` ×${p.n}` : ""} (${esc(p.PNPClass || "")}) — ${esc(p.Hint ? CM_SHORT[p.ConfigManagerErrorCode] || "ошибка" : CM_ERR[p.ConfigManagerErrorCode] || "ошибка, код " + p.ConfigManagerErrorCode)}${p.Hint ? `<div class="dev-hint">${esc(p.Hint)}</div>` : ""}`).join("<br>")}</div>`
      : d ? `<div class="note info">Все устройства работают без ошибок.</div>` : ""}
    ${d ? `<div class="grp">${dev ? "Драйверы устройств (кроме стандартных Microsoft)" : "Основные драйверы"}</div>
      <table class="t small">${(dev ? d.drivers : d.drivers.filter(x => ["DISPLAY", "NET", "MEDIA", "BLUETOOTH"].includes(x.DeviceClass))).map(x => {
        const isOld = old.includes(x);
        return `<tr><td>${esc(x.DeviceName)}</td><td class="sub">${esc(x.DeviceClass)}</td><td class="sub">${esc(x.DriverProviderName || "")}</td><td class="n">${esc(x.DriverVersion)}</td>
          <td class="n" ${isOld ? 'style="color:var(--warn)"' : ""}>${esc(x.Date || "")}${isOld ? " · старый" : ""}</td></tr>`}).join("")}</table>` : ""}
    <div class="sub">Сам ScanHub драйверы не ставит: это делают Windows Update и сайты производителей. Так безопаснее, а откат всегда возможен.</div>
  </div>`;
}

// ---------- защита от майнеров
function pProtect(dev){
  const h = TASK.hosts?.result, w = TASK.watch?.result;
  return `<div class="pnl">${head("Защита от майнеров", "Ничего не работает постоянно: блокировка — это строчки в файле hosts, сторож — короткая проверка по расписанию.")}
    <div class="toggle-card"><div><b>Блокировка майнинг-доменов</b>
      <div class="sub">Добавляет в hosts список NoCoin (~${h?.domains || "1000"} доменов). Браузерные майнеры и часть вредоносов перестанут достучаться до своих серверов. Нужны права администратора.</div>
      <div class="sub">${h ? (h.enabled ? `✓ включено, доменов: ${h.domains}` : "выключено") : "проверяю…"}</div>${taskBusy("hosts_set", "Жду подтверждения UAC…")}${taskErr("hosts_set")}</div>
      <button class="${h?.enabled ? "" : "primary"}" data-task-run="hosts_set" data-args='{"enable":${!h?.enabled}}'>${h?.enabled ? "Выключить" : "Включить"}</button></div>
    <div class="toggle-card"><div><b>Сторож</b>
      <div class="sub">Раз в 15 минут на 40 секунд смотрит, не грузит ли что-то процессор или видеокарту как майнер и нет ли обращений к майнинг-пулам. Если найдёт — пришлёт уведомление Windows. Это задача планировщика, а не постоянная программа.</div>
      <div class="sub">${w ? (w.enabled ? "✓ включён" : "выключен") : "проверяю…"}</div>${taskErr("watch_set")}</div>
      <button class="${w?.enabled ? "" : "primary"}" data-task-run="watch_set" data-args='{"enable":${!w?.enabled}}'>${w?.enabled ? "Выключить" : "Включить"}</button></div>
    ${w?.alerts?.length ? `<div class="grp">Срабатывания сторожа</div><div class="checks">${w.alerts.map(a => `<div class="check"><span class="ic ic-suspicious">!</span><span><b>${esc(a.time)}</b><span class="sub">${a.found.map(esc).join("<br>")}</span></span><span></span></div>`).join("")}</div>` : ""}
  </div>`;
}

// ---------- автозагрузка (разработчик)
let AR_ALL = false;
function pAutoruns(dev){
  const t = TASK.autoruns, items = t?.result || [];
  const shown = AR_ALL ? items : items.filter(i => i.level !== "ok");
  const btn = `<button class="primary" data-task-run="autoruns" ${t?.status === "running" ? "disabled" : ""}>${t?.result ? "Проверить снова" : "Проверить автозагрузку"}</button>`;
  return `<div class="pnl">${head("Автозагрузка", t?.result ? `${items.length} записей без системных; подозрительных ${items.filter(i => i.level === "bad").length}, внимания ${items.filter(i => i.level === "warn").length}` : "Реестр Run, папки автозагрузки, задачи планировщика, службы, WMI-подписки + проверка подписей", btn)}
    ${taskBusy("autoruns", "Собираю и проверяю подписи… до минуты")}${taskErr("autoruns")}
    ${t?.result ? `<label class="switch"><input type="checkbox" id="arAll" ${AR_ALL ? "checked" : ""}> показать и то, что в порядке</label>
    <div class="panel" style="margin:0"><table class="t small procs">${shown.map(i => `<tr><td><span class="lvl ${i.level}"></span>${esc(i.kind)}</td><td>${esc(i.name)}<div class="sub">${esc(i.flags.join("; ") || (i.sig?.signer || ""))}</div></td>
      <td class="mono" title="${esc(i.cmd || "")}">${esc(i.exe)}</td><td class="acts">${i.exe ? `<a data-open="${esc(i.exe)}">папка</a><a data-scan-exe="${esc(i.exe)}">проверить</a>` : ""}</td></tr>`).join("") || `<tr><td>Ничего подозрительного 👍</td></tr>`}</table></div>
    <div class="row-tools"><button data-launch="startup">Автозагрузка в Параметрах Windows</button>${tool("autoruns")?.ready ? `<button data-run="autoruns" data-mode="open">Открыть Autoruns</button>` : ""}</div>` : ""}
  </div>`;
}

// ---------- сеть (разработчик)
function pNetwork(dev){
  const t = TASK.network, n = t?.result;
  const btn = `<button data-task-run="network" ${t?.status === "running" ? "disabled" : ""}>Обновить</button>`;
  return `<div class="pnl">${head("Сеть", n ? `${n.connections.length} соединений · ${n.listening.length} открытых портов · ${n.dns_count} адресов в кэше DNS` : "", btn)}
    ${taskBusy("network", "Собираю соединения…")}${taskErr("network")}
    ${n ? `${n.pool_dns.length ? `<div class="note bad"><b>Были обращения к майнинг-пулам:</b> ${n.pool_dns.map(esc).join(", ")}</div>` : `<div class="note info">Обращений к известным майнинг-пулам в кэше DNS нет.</div>`}
    ${n.hosts_tampered.length ? `<div class="note bad"><b>Файл hosts блокирует антивирусы/обновления:</b><br>${n.hosts_tampered.map(esc).join("<br>")}</div>` : ""}
    <div class="grp">Активные соединения</div>
    <div class="panel" style="margin:0"><table class="t small procs"><tr><th>Процесс</th><th class="n">PID</th><th>Куда</th><th>Отметки</th><th></th></tr>${n.connections.slice(0, dev ? 200 : 30).map(c => `<tr ${c.flags.length ? 'style="background:var(--bad-bg)"' : ""}>
      <td>${esc(c.name)}</td><td class="n">${c.pid}</td><td class="mono">${esc(c.remote)}</td><td>${esc(c.flags.join("; "))}</td><td class="acts">${c.exe ? `<a data-open="${esc(c.exe)}">папка</a>` : ""}</td></tr>`).join("")}</table></div>
    <div class="grp">Открытые наружу порты</div>
    <div class="panel" style="margin:0"><table class="t small procs">${n.listening.map(l => `<tr><td>${esc(l.name)}</td><td class="n">${l.pid}</td><td class="mono">${esc(l.ip)}:${l.port}</td><td class="mono">${esc(l.exe)}</td></tr>`).join("")}</table></div>` : ""}
  </div>`;
}

// ---------- почему шумит
// процессы, которые показаны в разделе: по номеру строки открываются подробности (что это, где лежит, подпись, можно ли доверять)
let NOISE_P = [];
const npRef = r => { NOISE_P.push(r); return NOISE_P.length - 1 };
const PLACE = {system: "системная папка Windows", programs: "Program Files — установленная программа", user: "папка пользователя (AppData, Загрузки…)",
  temp: "временная папка", other: "другое место на диске", unknown: "путь не виден (защищённый системный процесс)"};
function safetyLine(r){
  if (r.mine) return ["ok", "Это сам ScanHub", "Нагрузка — от проверок и сбора данных, которые ты запускал в ScanHub."];
  if (r.safety === "safe") return ["ok", "Безопасен", `Подписан «${r.signer}»${r.place === "system" ? ", это часть Windows" : ", установленная программа"}.`];
  if (r.safety === "check") return ["warn", "Стоит проверить",
    `${r.signed ? `Подписан «${r.signer}», но` : "Без цифровой подписи и"} лежит в месте, откуда обычно запускаются скачанные программы: ${PLACE[r.place] || r.place}. ` +
    "Если не знаешь, что это, — проверь на вирусы."];
  if (r.place === "unknown") return ["ok", "Системный процесс", "Защищённый процесс Windows — его путь скрыт даже от администратора. Это нормально."];
  return ["info", r.signed ? "Похоже на обычную программу" : "Без подписи",
    r.signed ? `Подписан «${r.signer}».` : `Файл без цифровой подписи (${PLACE[r.place] || r.place}). Небольшие программы и игры часто не подписаны; если сомневаешься — проверь.`];
}
function procHtml(r){
  const [lvl, head, txt] = safetyLine(r);
  const meta = [r.avg != null ? `в среднем ${r.avg}%` : "", r.peak ? `пик ${Math.round(r.peak)}%` : "", r.count > 1 ? `процессов: ${r.count}` : "",
    r.rate ? fmtRate(r.rate) : ""].filter(Boolean).join(" · ");
  return `<div class="det-file">
    <div class="det-h"><b>${esc(r.name)}</b><span class="pill ${lvl === "ok" ? "ok" : lvl === "warn" ? "warn" : ""}">${esc(head)}</span></div>
    ${r.title ? `<div><b>Что это:</b> ${esc(r.title)}</div>` : `<div class="sub">ScanHub не знает эту программу — ориентируйся на подпись и место, где она лежит.</div>`}
    <div class="sub">${esc(txt)}</div>
    ${r.advice ? `<div class="sub">${esc(r.advice)}</div>` : ""}
    ${(r.services || []).length ? `<div class="sub">Службы внутри: ${esc(r.services.join(", "))}</div>` : ""}
    ${(r.cmds || []).length ? `<div class="sub">Что именно запущено:</div>${r.cmds.map(c => `<div class="mono sub">${esc(c)}</div>`).join("")}` : ""}
    ${r.exe ? `<div class="sub mono">${esc(r.exe)}</div>` : ""}
    ${meta ? `<div class="sub">Нагрузка: ${esc(meta)}</div>` : ""}
    ${r.exe ? `<div class="row-tools"><button class="small${r.safety === "check" ? " primary" : ""}" data-mdl="0" data-scan-exe="${esc(r.exe)}">Проверить на вирусы</button>
      <button class="small" data-mdl="0" data-open="${esc(r.exe)}">Открыть папку</button></div>` : ""}
  </div>`;
}
function showProc(i){
  const r = NOISE_P[i];
  if (r) modal({title: `${r.name}${r.title ? " — " + r.title : ""}`, icon: "i", ok: "Закрыть", cancel: null, wide: true, html: procHtml(r)});
}
function showPeak(){
  const p = TASK.noise?.result?.peak;
  if (!p?.procs?.length) return;
  modal({title: `Пик нагрузки ${Math.round(p.cpu)}% в ${p.at}`, icon: "i", ok: "Закрыть", cancel: null, wide: true,
    body: `${Math.max(1, Math.round(p.ago_s / 60))} мин назад. Кто в этот момент грузил процессор:`,
    html: p.procs.map(procHtml).join("")});
}
document.addEventListener("click", e => {
  const a = e.target.closest("[data-np],[data-noise-peak]");
  if (!a) return;
  e.preventDefault();
  if (a.hasAttribute("data-noise-peak")) showPeak(); else showProc(+a.dataset.np);
});
function pNoise(dev){
  NOISE_P = [];
  const t = TASK.noise, r = t?.result;
  const btn = `<button class="primary" data-task-run="noise" ${t?.status === "running" ? "disabled" : ""}>${r ? "Проверить ещё раз" : "Проверить сейчас"}</button>`;
  const intro = "Вентиляторы раскручиваются от нагрузки и тепла. Нажми, когда компьютер шумит: я 25 секунд понаблюдаю, кто нагружает процессор, видеокарту и диск, и учту, что было за последние 5 минут.";
  if (!r) return `<div class="pnl">${head("Почему шумит устройство", intro, btn)}
    ${taskBusy("noise", "Наблюдаю 25 секунд… можно продолжать работать как обычно")}${taskErr("noise")}</div>`;
  const ic = {bad: ["threat", "!"], warn: ["suspicious", "!"], info: ["pending", "i"], ok: ["clean", "✓"]};
  const main = r.causes.find(c => c.level !== "info") || r.causes[0];
  const mark = c => c.mine ? ` <span class="chip-note">ScanHub</span>` : c.safety === "check" ? ` <span class="chip-warn">проверь</span>` : "";
  const row = (c, extra) => `<tr><td><a data-np="${npRef(c)}" title="Что это и можно ли доверять">${esc(c.name)}</a>${c.count > 1 ? `<span class="sub"> ×${c.count}</span>` : ""}${mark(c)}${c.title ? `<div class="sub">${esc(c.title)}</div>` : ""}</td>${extra}
      <td class="acts">${c.exe ? `<a data-open="${esc(c.exe)}">папка</a>` : ""}${c.exe && !c.mine ? `<a data-scan-exe="${esc(c.exe)}" title="Проверить этот файл всеми сканерами">проверить на вирусы</a>` : ""}</td></tr>`;
  const idle = r.idle_s == null ? "" : r.idle_s >= 60 ? `не трогал компьютер ${Math.floor(r.idle_s / 60)} мин` : "компьютером пользуются";
  return `<div class="pnl">${head(esc(main?.title || "Готово"), `наблюдал ${r.observed_s} с · проверено ${esc((t.finished || "").replace("T", " "))}`, btn)}
    ${taskBusy("noise", "Наблюдаю 25 секунд…")}
    <div class="stats">
      <span>процессор <b style="color:var(--text)">${Math.round(r.cpu_total)}%</b> (${r.peak?.procs?.length ? `<a data-noise-peak title="Кто грузил процессор в момент пика">пик за 5 мин ${Math.round(r.cpu_peak5)}% — кто это был?</a>` : `пик за 5 мин ${Math.round(r.cpu_peak5)}%`})</span>
      ${r.gpu_now != null ? `<span>видеокарта <b style="color:var(--text)">${Math.round(r.gpu_now)}%</b>${r.gpu_temp != null ? ` · ${Math.round(r.gpu_temp)}°C` : ""}</span>` : ""}
      ${r.sensors?.cpu_temp ? `<span>процессор <b>${Math.round(r.sensors.cpu_temp)}°C</b></span>` : ""}
      ${r.sensors?.fans?.length ? `<span>вентиляторы <b>${r.sensors.fans.map(f => Math.round(f)).join(" / ")}</b> об/мин${r.sensors.fan_mode ? " · " + esc(r.sensors.fan_mode) : ""}</span>` : ""}
      <span>диск ${fmtRate(r.disk_now)}</span>
      ${idle ? `<span>${idle}</span>` : ""}
      ${r.power_mode ? `<span>режим питания: ${esc(r.power_mode.label)}</span>` : ""}
      ${r.battery ? `<span>${r.battery.plugged ? "от сети" : "от батареи"} · ${r.battery.percent}%</span>` : ""}
    </div>
    <div class="checks">${r.causes.map(c => `<div class="check"><span class="ic ic-${ic[c.level][0]}">${ic[c.level][1]}</span>
      <span><b>${esc(c.title)}</b>${c.text ? `<span class="sub">${esc(c.text)}</span>` : ""}</span>
      <span>${c.action === "peak" ? `<button class="small primary" data-noise-peak>Кто это был</button>`
        : c.action === "proc" && c.proc ? `<button class="small" data-np="${npRef(c.proc)}">Что это</button>`
        : c.action === "scan" && c.path ? `<button class="small" data-scan-exe="${esc(c.path)}">Проверить</button>` : ""}</span></div>`).join("")}</div>
    <div class="charts" style="margin-top:4px">
      <div><div class="grp">Грузят процессор сейчас</div>
        <table class="t small procs">${r.top_cpu.map(c => row(c, `<td class="n">${c.avg}%</td>`)).join("") || `<tr><td class="sub">никто заметно не грузит</td></tr>`}</table></div>
      ${r.peak?.procs?.length ? `<div><div class="grp">В момент пика ${Math.round(r.peak.cpu)}% (${esc(r.peak.at)})</div>
        <table class="t small procs">${r.peak.procs.map(c => row(c, `<td class="n">${c.avg}%</td>`)).join("")}</table></div>` : ""}
      <div><div class="grp">За последние 5 минут</div>
        <table class="t small procs">${r.top_5m.map(c => row(c, `<td class="n">${c.avg}%${c.count > 1 ? "" : `<span class="sub"> · пик ${Math.round(c.peak)}%</span>`}</td>`)).join("") || `<tr><td class="sub">спокойно</td></tr>`}</table></div>
      ${r.gpu_culprits.length ? `<div><div class="grp">Видеокарта</div><table class="t small procs">${r.gpu_culprits.map(g => `<tr><td>${esc(g.name)}${g.engine ? `<div class="sub">${esc(g.engine)}</div>` : ""}</td><td class="n">${g.avg}%</td></tr>`).join("")}</table></div>` : ""}
      ${r.top_io.length ? `<div><div class="grp">Диск</div><table class="t small procs">${r.top_io.map(c => row(c, `<td class="n">${fmtRate(c.rate)}</td>`)).join("")}</table></div>` : ""}
    </div>
    ${r.note ? `<div class="sub">${esc(r.note)}</div>` : ""}
  </div>`;
}

// ---------- комплектующие
const MEM_TYPE = {20: "DDR", 21: "DDR2", 24: "DDR3", 26: "DDR4", 29: "LPDDR3", 30: "LPDDR4", 34: "DDR5", 35: "LPDDR5"};
const MEM_FORM = {8: "DIMM", 12: "SO-DIMM", 13: "SO-DIMM"};
const GBn = b => b ? (b / 2 ** 30 >= 1000 ? (b / 2 ** 40).toFixed(1) + " ТБ" : Math.round(b / 2 ** 30) + " ГБ") : "—";
function hwModel(h){
  const sys = h.system || {}, out = [];
  out.push({ic: sys.type === 2 ? "💻" : "🖥", t: "Устройство", main: [sys.maker, sys.family || sys.model].filter(Boolean).join(" "),
    rows: [["Тип", sys.type === 2 ? "ноутбук" : "настольный ПК"], ["Модель", sys.model], ["Материнская плата", sys.board], ["BIOS", [sys.bios, sys.bios_date].filter(Boolean).join(" от ")]]});
  for (const c of h.cpu || []) out.push({ic: "⚙️", t: "Процессор", main: c.name,
    rows: [["Ядра / потоки", `${c.cores} / ${c.threads}`], ["Частота", c.mhz ? (c.mhz / 1000).toFixed(1) + " ГГц (база)" : ""], ["Кэш L2 / L3", `${c.l2 ? c.l2 / 1024 + " МБ" : "—"} / ${c.l3 ? c.l3 / 1024 + " МБ" : "—"}`], ["Сокет", c.socket]]});
  const r = h.ram || {}, mods = r.modules || [];
  if (mods.length || r.total) {
    const m0 = mods[0] || {};
    out.push({ic: "🧠", t: "Оперативная память", main: `${GBn(mods.reduce((a, m) => a + (m.size || 0), 0) || r.total)} ${MEM_TYPE[m0.type] || ""}${m0.speed ? "-" + m0.speed : ""}`.trim(),
      rows: [["Планки", `${mods.length} из ${r.slots || "?"} слотов (${MEM_FORM[m0.form] || "?"})`], ["Максимум", r.max_kb ? Math.round(r.max_kb / 2 ** 20) + " ГБ" : ""],
             ...mods.map((m, i) => [`Планка ${i + 1}`, `${GBn(m.size)} · ${(m.maker || "").trim()} ${m.part || ""} · ${m.cfg || m.speed} МТ/с`])]});
  }
  for (const g of h.gpu || []) out.push({ic: "🎮", t: "Видеокарта", main: g.name,
    rows: [["Видеопамять", g.vram ? GBn(g.vram) : ""], ["Драйвер", [g.driver, g.driver_date].filter(Boolean).join(" от ")], ["Сейчас выводит", g.res ? `${g.res}${g.hz ? " · " + g.hz + " Гц" : ""}` : ""]]});
  for (const d of h.disks || []) out.push({ic: "💾", t: "Накопитель", main: d.name,
    rows: [["Объём", GBn(d.size)], ["Тип", [d.bus === "NVMe" ? "NVMe" : d.bus, d.media && d.media !== "Unspecified" ? d.media : ""].filter(Boolean).join(" ")], ["Состояние", d.health === "Healthy" ? "исправен" : d.health]]});
  for (const m of h.monitors || []) {
    const diag = m.w_cm && m.h_cm ? (Math.sqrt(m.w_cm ** 2 + m.h_cm ** 2) / 2.54).toFixed(1) + "″" : "";
    const g0 = (h.gpu || []).find(g => g.res);
    out.push({ic: "🖵", t: "Экран", main: [m.name || "Встроенный экран", diag].filter(Boolean).join(" · "),
      rows: [["Производитель панели", m.maker], ["Год выпуска", m.year], ["Разрешение", g0 ? `${g0.res}${g0.hz ? " · " + g0.hz + " Гц" : ""}` : ""]]});
  }
  if ((h.net || []).length) out.push({ic: "🌐", t: "Сеть", main: h.net.find(n => n.status === "Up")?.name || h.net[0].name,
    rows: h.net.map(n => [n.alias || "адаптер", `${n.name}${n.status === "Up" ? " · " + n.speed : " · не подключён"}`])});
  const extra = [...(h.audio || []).map(a => ["Звук", a.name]), ...(h.camera || []).map(c => ["Камера", c]), ...(h.bluetooth || []).map(b => ["Bluetooth", b])];
  if (extra.length) out.push({ic: "🎧", t: "Звук, камера, Bluetooth", main: "", rows: extra});
  const b = h.battery;
  if (b && b.design) {
    const wear = Math.max(0, Math.round((1 - b.full / b.design) * 100));
    out.push({ic: "🔋", t: "Батарея", main: `${Math.round(b.full / 1000)} из ${Math.round(b.design / 1000)} Вт·ч · износ ${wear}%`,
      rows: [["Модель", [b.maker, b.name].filter(Boolean).join(" ")], ["Циклов зарядки", b.cycles], ["Тип", {6: "литий-ионная", 8: "литий-полимерная"}[b.chem] || ""]]});
  }
  const os = h.os || {};
  out.push({ic: "🪟", t: "Windows", main: `${os.name || ""} ${os.display || ""}`.trim(),
    rows: [["Сборка", os.build], ["Разрядность", os.arch], ["Установлена", os.installed]]});
  return out;
}
function hwText(h){
  return hwModel(h).map(c => `${c.t}: ${c.main}\n` + c.rows.filter(r => r[1] != null && r[1] !== "").map(r => `  ${r[0]}: ${r[1]}`).join("\n")).join("\n\n");
}
// проверка комплектующих: что работает не в полную силу, подключено не так или конфликтует (hwcheck.py)
const HW_IC = {bad: ["threat", "!"], warn: ["suspicious", "!"], info: ["running", "i"], ok: ["clean", "✓"]};
function hwCheckBox(){
  const c = TASK.hwcheck, r = c?.result, items = r?.items || [];
  const probs = items.filter(i => i.lvl !== "ok"), fine = items.filter(i => i.lvl === "ok");
  const nb = probs.filter(i => i.lvl === "bad").length, nw = probs.filter(i => i.lvl === "warn").length, ni = probs.filter(i => i.lvl === "info").length;
  const sum = !r ? "" : !probs.length ? "Всё работает как надо." :
    [nb && `серьёзных: ${nb}`, nw && `замечаний: ${nw}`, ni && `советов: ${ni}`].filter(Boolean).join(" · ");
  const ic = l => `<span class="ic ic-${HW_IC[l][0]}">${HW_IC[l][1]}</span>`;
  return `<div class="pnl inner hwcheck">
    <div class="head"><div><h4 style="margin:0">Проверка комплектующих</h4>
      <div class="sub">${r ? `${esc(sum)} Проверено ${esc(ago(r.collected))}.` : "Ищу то, что работает не в полную силу, подключено не так или конфликтует."}</div></div>
      <div class="grow"></div><button class="${r ? "small" : "primary small"}" data-task-run="hwcheck" ${c?.status === "running" ? "disabled" : ""}>${r ? "Проверить снова" : "Проверить"}</button></div>
    ${taskBusy("hwcheck", "Проверяю память, видеокарту, экран, питание, BIOS, устройства и сеть… несколько секунд")}${taskErr("hwcheck")}
    ${probs.length ? `<div class="checks">${probs.map(i => `<div class="check">${ic(i.lvl)}<span><b>${esc(i.title)}</b>
        <span class="sub"><span class="chip-note">${esc(i.comp)}</span> ${esc(i.text || "")}</span>${i.how ? `<span class="sub how">Что сделать: ${esc(i.how)}</span>` : ""}</span>
        <span class="acts">${aiBtn(i.title, `${i.comp}: ${i.text || ""}${i.how ? " Что сделать: " + i.how : ""}`, {source: "Здоровье ПК · Комплектующие"})}${i.page ? `<button class="small" data-go-page="${esc(i.page)}">Открыть</button>` : ""}</span></div>`).join("")}</div>` : ""}
    ${fine.length ? `<details class="ud"${probs.length ? "" : " open"}><summary class="sub">что в порядке (${fine.length})</summary>
      <div class="uitems">${fine.map(i => `<div class="urow"><span class="ic ic-clean">✓</span><span><b>${esc(i.title)}</b></span><span></span></div>`).join("")}</div></details>` : ""}
    <div class="sub">Проверяется: частота и каналы памяти, шина PCIe и мощность видеокарты, частота экрана, зарядка и настройки питания, обновление BIOS,
      устройства с ошибками и конфликтами, скорость сетевого кабеля, сигнал Wi-Fi, перегрев и аппаратные сбои.</div>
  </div>`;
}
function pHw(dev){
  const t = TASK.hardware, h = t?.result;
  const btns = `${h ? `<button data-hw-copy>Скопировать сводку</button>` : ""}<button data-task-run="hardware" data-args='{"refresh":true}' ${t?.status === "running" ? "disabled" : ""}>${h ? "Обновить" : "Собрать"}</button>`;
  return `<div class="pnl">${head("Комплектующие", h ? `собрано ${esc((h.collected || "").replace("T", " "))}` : "Процессор, память, видеокарта, накопители, экран, сеть, батарея — всё на одной странице", btns)}
    <div data-gpu-live>${gpuLiveHtml()}</div>
    ${hwCheckBox()}
    ${taskBusy("hardware", "Собираю сведения о комплектующих… около минуты (потом сохранится и будет открываться сразу)")}${taskErr("hardware")}
    ${h ? `<div class="hwgrid">${hwModel(h).map(c => `<div class="hwcard"><div class="hwhead"><span class="hwic">${c.ic}</span><span><span class="sub">${esc(c.t)}</span><b>${esc(c.main || "")}</b></span></div>
      <table>${c.rows.filter(r => r[1] != null && r[1] !== "").map(r => `<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td></tr>`).join("")}</table></div>`).join("")}</div>` : ""}
  </div>`;
}

// ---------- программы
function pApps(dev){
  const t = TASK.apps, apps = t?.result || [];
  return `<div class="pnl">${head("Проверить программу", "Выбери программу — её папку проверят все сканеры: Defender, ClamAV, YARA, Atomdrift, цифровые подписи, а онлайн — VirusTotal и Filescan (только хэши).")}
    ${taskBusy("apps", "Собираю список установленных программ…")}${taskErr("apps")}
    ${apps.length ? `<input type="text" class="search" placeholder="Поиск: Telegram, Chrome, Steam…" spellcheck="false">
    <div class="applist">${apps.map(a => `<div class="app" data-name="${esc((a.name + " " + a.publisher).toLowerCase())}"><span><b>${esc(a.name)}</b><span class="sub">${esc(a.publisher)}${a.version ? " · " + esc(a.version) : ""}${dev ? " · " + esc(a.path) : ""}</span></span>
      <span class="acts"><button class="small primary" data-scan-exe="${esc(a.path)}">Проверить</button></span></div>`).join("")}</div>` : ""}
  </div>`;
}
function filterApps(input){
  const q = input.value.trim().toLowerCase();
  input.closest(".pnl").querySelectorAll(".app").forEach(a => a.hidden = q && !a.dataset.name.includes(q));
}

// ---------- события панелей
document.addEventListener("input", e => { if (e.target.matches(".pnl input.search")) filterApps(e.target) });
document.addEventListener("change", e => {
  if (e.target.id === "arAll") { AR_ALL = e.target.checked; redrawPanels() }
  if (e.target.id === "hSys") store.set("hsys", e.target.checked ? "1" : "0");
});
document.addEventListener("click", async e => {
  const el = e.target.closest("[data-panel],[data-panel-go],[data-sys],[data-task-run],[data-launch],[data-stop-job],[data-show-deep],[data-force-install],[data-noise-go],[data-hwcheck-go],[data-hw-copy],[data-memclean],#deepStart,#cleanGo,#healthStart");
  if (!el) return;
  if (el.dataset.panel) return openPanel(el.dataset.panel);
  if (el.hasAttribute("data-memclean")) { runTask(M?.memclean_on ? "mem_full" : "mem_quick").then(() => pollMetrics()); return }
  if (el.hasAttribute("data-hw-copy")) {
    const txt = hwText(TASK.hardware.result);
    try { await navigator.clipboard.writeText(txt); el.textContent = "Скопировано ✓"; toast("Сводка скопирована", "можно вставить в чат или на форум") } catch { modal({title: "Скопируй сводку", body: "Буфер обмена недоступен — выдели текст и нажми Ctrl+C.", copy: txt, ok: "Готово", cancel: null, icon: "i"}) }
    setTimeout(() => el.textContent = "Скопировать сводку", 2000); return;
  }
  if (el.hasAttribute("data-noise-go")) { goPanel("noise"); return runTask("noise") }
  if (el.hasAttribute("data-hwcheck-go")) { goPanel("hw"); return runTask("hwcheck") }      // всегда свежая проверка, не прошлый итог
  if (el.dataset.panelGo) return goPanel(el.dataset.panelGo);
  if (el.dataset.sys) return showSys(el.dataset.sys);
  if (el.dataset.launch === "sfc_repair" && !await ask("Запустить восстановление системных файлов? Откроется окно администратора: сначала DISM скачает исправные файлы (нужен интернет), потом SFC заменит повреждённые. 15–30 минут, затем перезагрузка. Не закрывай окно до конца.")) return;
  if (el.dataset.launch && el.dataset.confirm && !await ask(el.dataset.confirm)) return;
  if (el.dataset.launch) return api("/api/launch", {what: el.dataset.launch})
    .then(() => toast("Открыто: " + (LAUNCH_NAMES[el.dataset.launch] || el.dataset.launch), "", "info"))
    .catch(err => toast("Не удалось открыть", err.message, "err"));
  if (el.dataset.stopJob && el.dataset.confirm && !await ask(el.dataset.confirm)) return;
  if (el.dataset.stopJob) return api("/api/stop", {id: el.dataset.stopJob}).then(() => toast("Проверка остановлена", "", "info"));
  if (el.dataset.forceInstall) {
    if (!await ask("Эту версию придержали: на неё ругаются антивирусы или Defender. Ставить всё равно? Defender может снова её заблокировать.")) return;
    await api("/api/install", {tool: el.dataset.forceInstall, update: true, force: true});
    return refresh();
  }
  if (el.dataset.showDeep) { follow(el.dataset.showDeep); return }
  if (el.dataset.taskRun) {
    if (el.dataset.confirm && !await ask(el.dataset.confirm)) return;
    const args = el.dataset.args ? JSON.parse(el.dataset.args) : {};
    if (el.hasAttribute("data-rp")) args.restore_point = rpOn();
    const name = el.dataset.taskRun;
    if (name === "disk_analyze") DISK_VIEW = null;
    const t = await runTask(name, args);
    return afterTask(name, args, t);
  }
  if (el.id === "healthStart") {
    const withSys = $("#hSys")?.checked, withDisk = $("#hDisk")?.checked;
    store.set("hsys", withSys ? "1" : "0"); store.set("hdisk", withDisk ? "1" : "0");
    delete TASK.sysfiles;
    if (withSys || withDisk) runTask("sysfiles", {sfc: !!withSys, disk: !!withDisk});
    runTask("firewall", undefined, true);
    return runTask("health");
  }
  if (el.id === "deepStart") {
    if (!await ask("Глубокая проверка займёт 15–40 минут. Windows один раз попросит права администратора — это для проверки всех процессов. Начать?")) return;
    const r = await api("/api/deep", {});
    DEEP = {id: r.id, data: null}; store.set("deep", r.id);
    if (MODE === "dev") follow(r.id, true);
    return pollDeep();
  }
});
// после загрузки всех файлов окна: иначе ответ сервера может прийти раньше pages.js, где redrawPanels
window.addEventListener("DOMContentLoaded", () => api("/api/jobs").then(r => { const d = r.jobs.find(j => j.tool === "deep"); if (d) { DEEP.id = d.id; store.set("deep", d.id) } if (DEEP.id) pollDeep() }).catch(() => {}));

