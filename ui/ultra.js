// ============================================================ УЛЬТРА ПРОВЕРКА: все проверки приложения подряд
let ULTRA = {plan: [], job: null, setup: false, polling: false, notified: null};
const U_IC = {threat: ["threat", "!"], bad: ["threat", "!"], warn: ["suspicious", "!"], info: ["running", "i"], ok: ["clean", "✓"],
  error: ["error", "!"], skipped: ["skipped", "–"]};
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------- выбор шагов (запоминается)
function ultraDefaults(){
  return {steps: ULTRA.plan.map(p => p.id), opts: Object.fromEntries(ULTRA.plan.map(p => [p.id, (p.opts || []).filter(o => o.on).map(o => o.id)]))};
}
function ultraSel(){
  const d = ultraDefaults();
  let s = null;
  try { s = JSON.parse(store.get("ultra") || "null") } catch {}
  if (!s?.steps || !s?.opts) return d;
  s.steps = s.steps.filter(id => ULTRA.plan.some(p => p.id === id));
  for (const p of ULTRA.plan) if (!(p.id in s.opts)) { s.opts[p.id] = d.opts[p.id]; s.steps.push(p.id) }   // новый шаг после обновления
  return s;
}
const ultraSave = s => store.set("ultra", JSON.stringify(s));
function ultraMins(S){
  return ULTRA.plan.filter(p => S.steps.includes(p.id))
    .reduce((a, p) => a + p.mins + (p.opts || []).filter(o => o.mins && S.opts[p.id]?.includes(o.id)).reduce((x, o) => x + o.mins, 0), 0);
}
function ultraUac(S){
  const has = (step, ...ids) => S.steps.includes(step) && ids.some(i => S.opts[step]?.includes(i));
  // всё после глубокой проверки, что требует администратора, идёт одним окном
  return (S.steps.includes("deep") ? 1 : 0) + (has("clean", "junk", "junk_more", "drv") || has("health", "sfc", "disk") ? 1 : 0);
}
const minsText = m => m >= 60 ? `${Math.floor(m / 60)} ч ${m % 60 ? m % 60 + " мин" : ""}`.trim() : `${m} мин`;
const timesText = n => `${n} ${n === 1 ? "раз" : "раза"}`;
function elapsedText(from, to){
  const s = Math.max(0, Math.round(((to ? new Date(to) : Date.now()) - new Date(from)) / 1000));
  return s >= 3600 ? `${Math.floor(s / 3600)}:${String(Math.floor(s / 60) % 60).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`
                   : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

// ---------- кнопки действий из находок
function ultraAct(a, primary){
  if (!a) return "";
  const cls = `small${primary ? " primary" : ""}`, lab = esc(a.label || "Открыть"), cf = a.confirm ? ` data-confirm="${esc(a.confirm)}"` : "";
  if (a.deep) return `<button class="${cls}" data-ultra-deep="${esc(a.deep)}">${lab}</button>`;
  if (a.task) return `<button class="${cls}" data-ultra-task="${esc(a.task)}" data-page="${esc(a.page || "")}"${cf}>${lab}</button>`;
  if (a.launch) return `<button class="${cls}" data-launch="${esc(a.launch)}"${cf}>${lab}</button>`;
  if (a.install) return `<button class="${cls}" data-install="${esc(a.install)}">${lab}</button>`;
  if (a.run) return `<button class="${cls}" data-run="${esc(a.run[0])}" data-mode="${esc(a.run[1])}">${lab}</button>`;
  if (a.link) return `<button class="${cls}" data-link="${esc(a.link)}">${lab}</button>`;
  if (a.page) return `<button class="${cls}" data-go-page="${esc(a.page)}">${lab}</button>`;
  return "";
}
const uIcon = (lvl, size = "") => `<span class="ic ic-${(U_IC[lvl] || U_IC.info)[0]}${size}">${(U_IC[lvl] || U_IC.info)[1]}</span>`;
function ultraItems(items, all){
  const list = all ? items : items.filter(i => i.lvl !== "ok");
  if (!list.length) return "";
  return `<div class="uitems">${list.map(i => `<div class="urow">${uIcon(i.lvl)}<span class="x"><b>${esc(i.t)}</b>${i.s ? `<span class="sub">${esc(i.s)}</span>` : ""}</span>
    <span class="acts">${i.lvl === "ok" ? "" : aiBtn(i.t, i.s, {source: "Ультра проверка"})}${ultraAct(i.a)}</span></div>`).join("")}</div>`;
}

// ---------- экраны
function pUltra(dev){
  if (!ULTRA.plan.length) return pnl(head("Ультра проверка устройства", "Загружаю…"));
  const j = ULTRA.job;
  if (j?.status === "running") return ultraRunning(j, dev);
  if (j && !ULTRA.setup) return ultraDone(j, dev);
  return ultraSetup();
}

function ultraSetup(){
  const S = ultraSel(), on = id => S.steps.includes(id);
  const mins = ultraMins(S), uac = ultraUac(S);
  const rows = ULTRA.plan.map((p, i) => `<div class="ustep${on(p.id) ? "" : " off"}">
      <label class="crow"><input type="checkbox" data-ultra-step="${p.id}" ${on(p.id) ? "checked" : ""}>
        <span><b>${i + 1}. ${esc(p.title)}</b>${p.admin ? " " + adminChip : ""}<span class="sub">${esc(p.hint)}</span></span>
        <span class="n sub">≈ ${p.mins} мин</span></label>
      ${(p.opts || []).length && on(p.id) ? `<div class="uopts">${p.opts.map(o => `<label class="crow tight"><input type="checkbox" data-ultra-opt="${p.id}|${o.id}" ${S.opts[p.id]?.includes(o.id) ? "checked" : ""}>
          <span><b>${esc(o.t)}</b>${o.admin ? " " + adminChip : ""}<span class="sub">${esc(o.d)}</span></span><span class="n sub">${o.mins ? "+" + o.mins + " мин" : ""}</span></label>`).join("")}</div>` : ""}
    </div>`).join("");
  return pnl(`${head("Ультра проверка устройства", "Все проверки ScanHub подряд — от вирусов до сбоев и мусора. В конце — общий итог и что стоит сделать.")}
    ${explain("Отметь, что проверять, и нажми «Начать». Шаги идут по очереди, окно можно свернуть — проверка продолжится, а в конце придёт уведомление. " +
      "Ничего важного ScanHub не удаляет: в очистке только мусор и кэши, у ярлыков и настроек сохраняются копии. Всё, что нужно решить тебе (удалить, выключить, поменять), будет в итогах кнопками.")}
    <div class="row-tools"><button data-ultra-preset="all">Отметить всё</button><button data-ultra-preset="default">Как по умолчанию</button><button data-ultra-preset="none">Снять всё</button></div>
    <div class="usteps">${rows}</div>
    <div class="note info">В конце ScanHub посоветует, что сделать вручную: проверить компьютер Dr.Web CureIt!, KVRT, ESET Online Scanner, Malwarebytes, MinerSearch и Microsoft Safety Scanner
      (они работают только своим окном), удалить лишние встроенные приложения и пересмотреть автозагрузку.</div>
    <div class="stickybar"><span>Шагов: <b>${S.steps.length}</b> · около <b>${minsText(mins)}</b>${uac ? ` · Windows попросит права администратора ${timesText(uac)}` : ""}</span><div class="grow"></div>
      ${ULTRA.job ? `<button data-ultra-back>К прошлым итогам</button>` : ""}<button class="primary" data-ultra-start ${S.steps.length ? "" : "disabled"}>Начать ультра проверку</button></div>`);
}

function ultraStepIcon(s, i){
  if (s.status === "running") return `<span class="ic ic-running"><div class="spin"></div></span>`;
  if (s.status === "pending") return `<span class="ic ic-pending">${i + 1}</span>`;
  return uIcon(s.verdict === "skipped" ? "skipped" : s.verdict || "ok");
}

function ultraRunning(j, dev){
  const steps = j.steps || [], n = steps.length;
  const done = steps.filter(s => s.status === "done" || s.status === "skipped").length;
  const cur = steps.find(s => s.status === "running");
  return pnl(`<div class="head"><div class="result" style="padding:0;border:0;background:none"><div class="big"><div class="icon i-run"><div class="spin"></div></div>
      <div><h3 style="margin:0">Идёт ультра проверка${n ? `… шаг ${Math.min(done + 1, n)} из ${n}` : "…"}</h3>
      <div class="sub">прошло <span data-since="${esc(j.started)}">${elapsedText(j.started)}</span> · можно свернуть окно — проверка продолжится</div></div></div></div><div class="grow"></div>
      <button class="danger" data-stop-job="${esc(j.id)}" data-confirm="Остановить ультра проверку? Уже выполненные шаги сохранятся в итогах.">Остановить</button></div>
    <div class="progress"><div style="width:${n ? (done + (cur ? 0.5 : 0)) / n * 100 : 3}%"></div></div>
    ${cur?.progress && /UAC/.test(cur.progress) ? `<div class="note warn"><b>Подтверди окно UAC.</b> Windows спрашивает разрешение администратора — без него этот шаг будет ждать.</div>` : ""}
    <ul class="steps">${steps.map((s, i) => {
      const open = s.status === "running" || ULTRA.openStep?.[s.id];
      return `<li class="ustep${open ? " open" : ""}" data-ustep="${esc(s.id)}" title="Нажми — что делает этот шаг">${ultraStepIcon(s, i)}
      <span class="t"><b>${esc(s.title)}</b><span class="sub">${s.status === "running" ? esc(s.progress || s.hint) + (s.started ? ` · <span data-since="${esc(s.started)}">${elapsedText(s.started)}</span>` : "") : esc(s.hint)}</span>
        ${s.status === "running" ? ultraLive(j) : open ? ultraStepInfo(s) : ""}
        ${s.status === "done" ? ultraItems(s.items, dev) : ""}</span>
      <span class="lbl">${s.status === "pending" ? "ждёт" : s.status === "running" ? "идёт…" : esc(s.label)}</span></li>`}).join("")}</ul>`);
}

// «живая» строка текущего шага: что за процесс работает, грузит ли он процессор, растёт ли «прочитано» — видно, что не зависло
function ultraLive(j){
  const L = j.live || {}, q = L.quiet_s ?? 0;
  const proc = L.name ? `Работает <b>${esc(L.name)}</b>: процессор ${L.cpu ?? 0}% · прочитано с диска ${fmtB(L.read || 0)} · памяти ${fmtB(L.mem || 0)}` : "Работает ScanHub";
  const quiet = q < 5 ? "журнал только что обновился" : `журнал обновлялся ${q} с назад`;
  const warn = q > 600 && !(L.cpu > 0.5) ? `<div class="note warn">Уже 10 минут тихо и процессор не занят — похоже, шаг завис. Можно нажать «Остановить» и запустить проверку заново.</div>`
    : q > 60 && L.name ? `<div class="sub">Сканер может долго молчать, пока проверяет большой файл или архив. Всё в порядке, если процессор занят или растёт «прочитано».</div>` : "";
  return `<div class="ulive"><span class="pulse"></span><span>${proc} · ${quiet}</span></div>${warn}
    ${j.tail?.length ? `<details class="ulog" id="ultraLog" ${ULTRA.logOpen ? "open" : ""}><summary>Журнал шага <span class="sub">— ${esc(j.tail_of || "")}, последние строки</span></summary>
      <pre>${esc(j.tail.join("\n"))}</pre>${MODE === "dev" ? `<div class="sub">Полный журнал — в «⌨ Консоли».</div>` : ""}</details>` : ""}`;
}
function ultraStepInfo(s){
  const took = s.started && s.finished ? `занял ${elapsedText(s.started, s.finished)}` : s.status === "pending" ? "ещё не начинался" : "";
  return `<div class="ustep-info">${esc(s.hint || "")}${took ? ` <span class="sub">· ${took}</span>` : ""}${s.status === "done" && s.id === "deep" ? ` <a data-go-page="scan:deep">Подробные итоги глубокой проверки</a>` : ""}</div>`;
}
document.addEventListener("click", e => {
  const li = e.target.closest("[data-ustep]");
  if (!li || e.target.closest("button,a,details,summary,input,.uitems")) return;
  const id = li.dataset.ustep;
  ULTRA.openStep = {...(ULTRA.openStep || {}), [id]: !ULTRA.openStep?.[id]};
  redrawPanels();
});
setInterval(() => document.querySelectorAll("[data-since]").forEach(el => { el.textContent = elapsedText(el.dataset.since) }), 1000);   // часы тикают сами, не дожидаясь ответа сервера

// Итоги ультра проверки — снимок на момент проверки. Всё, что можно сверить с текущим состоянием, сверяем заново
// при каждом открытии итогов: исправленное (кнопкой здесь, в мастере или в разделе) само становится «исправлено».
// now(item, result) → {ok, text} или null (данных нет). noRun — задачу сам не запускаем (нужен UAC), берём последний итог.
const pct = d => Math.round(100 - d.percent);
const diskNow = (i, m) => {
  const mt = i.t.match(/^(?:Диск |На )([A-Z]:)/), d = mt && (m?.now?.disks || []).find(x => x.mount === mt[1]);
  return d ? {ok: pct(d) >= 20, text: `сейчас свободно ${fmtB(d.total - d.used)} (${pct(d)}%)`} : null;
};
const RECHECK = [
  {re: /^Не выключено рекомендуемых настроек приватности/, task: "privacy",
   now: (i, r) => Array.isArray(r) ? (n => ({ok: !n, text: `сейчас не выключено: ${n}`}))(r.filter(x => x.rec && !x.applied).length) : null},
  {re: /^Выключены защиты Windows/, task: "security",
   now: (i, r) => Array.isArray(r) ? (n => ({ok: !n, text: `сейчас выключено: ${n}`}))(r.filter(x => x.rec && x.ok === false).length) : null},
  {re: /^Лишние записи в PATH/, task: "envpath",
   now: (i, r) => Array.isArray(r?.entries) ? (n => ({ok: !n, text: `сейчас: ${n}`}))(r.entries.filter(e => e.problem).length) : null},
  {re: /^Точки восстановления выключены/, task: "restore", now: (i, r) => r ? {ok: r.enabled === true} : null},
  {re: /^В меню правой кнопки — пункты от удалённых программ/, task: "ctx",
   now: (i, r) => Array.isArray(r?.items) ? (n => ({ok: !n, text: `сейчас: ${n}`}))(r.items.filter(x => x.exists === false && x.enabled).length) : null},
  {re: /^Записи автозагрузки без файла/, task: "startup",
   now: (i, r) => Array.isArray(r?.items) ? (n => ({ok: !n, text: `сейчас: ${n}`}))(r.items.filter(x => x.enabled && x.missing).length) : null},
  {re: /^(Диск [A-Z]: — свободно|На [A-Z]: свободно)/, metrics: true, now: diskNow},
  {re: /^Устройства с ошибками/, task: "drivers",
   now: (i, r) => Array.isArray(r?.problems) ? {ok: !r.problems.length, text: `сейчас: ${r.problems.length}` + (r.problems[0] ? ` — ${r.problems[0].Name}` : "")} : null},
  {re: /^Windows Update нашёл драйверы/, task: "driver_updates", ttl: 900,
   now: (i, r) => Array.isArray(r) ? {ok: !r.length, text: `сейчас: ${r.length}`} : null},
  {re: /^Правила брандмауэра с замечаниями/, task: "firewall",
   now: (i, r) => r?.warn != null ? {ok: !r.warn, text: `сейчас: ${r.warn}`} : null},
  {re: /^Удалённые программы в списке Windows/, task: "winget", ttl: 900,
   now: (i, r) => Array.isArray(r?.apps) ? (n => ({ok: !n, text: `сейчас: ${n}`}))(r.apps.filter(a => a.ghost).length) : null},
  // находки «Комплектующих» помечены src: "hwcheck" — сверяем по заголовку с новой проверкой
  {match: i => i.src === "hwcheck", task: "hwcheck", ttl: 300,
   now: (i, r) => Array.isArray(r?.items) ? {ok: !r.items.some(x => x.title === i.t && x.lvl !== "ok")} : null},
  // сбои — история за 30 дней: пункт решён, когда свежий разбор журналов больше не считает его поводом что-то делать
  // (разовый старый сбой — норма; см. diag._summary)
  {re: /^(Сбоев видеодрайвера|Вылетов программ|Внезапных выключений|Ошибок диска|Синих экранов|Аппаратных ошибок)/, task: "diag", ttl: 900,
   now: (i, r) => Array.isArray(r?.summary) ? (k => ({ok: !r.summary.some(x => ["warn", "bad"].includes(x.lvl) && x.text.startsWith(k))}))(i.t.split(":")[0]) : null},
  {re: /^Хранилище компонентов Windows повреждено/, task: "sysfiles", noRun: true, now: (i, r) => r?.dism ? {ok: r.dism === "ok"} : null},
  {re: /^Найдены повреждённые системные файлы/, task: "sysfiles", noRun: true, now: (i, r) => r?.sfc ? {ok: r.sfc === "ok"} : null},
];
const RC = {asked: {}, metrics: null};
const rcHit = (c, i) => c.match ? c.match(i) : c.re.test(i.t);
async function rcTask(t, ttl, noRun){
  const now = Date.now();
  if (RC.asked[t] && now - RC.asked[t] < ttl * 1000) return;
  RC.asked[t] = now;
  try {
    let cur = TASK[t];
    if (cur?.status !== "running") { cur = await api(`/api/task?name=${t}`); if (cur.status !== "none") TASK[t] = cur }
    if (cur.status === "running") return runTask(t, undefined, true);
    const age = cur.finished ? now - new Date(cur.finished) : Infinity;
    if (!noRun && (cur.status !== "done" || age > ttl * 1000)) return runTask(t, undefined, true);   // сама перерисует окно
    redrawPanels();
  } catch {}
}
function recheckUltra(items){
  const used = RECHECK.filter(c => items.some(i => rcHit(c, i)));
  for (const c of used) if (c.task) rcTask(c.task, c.ttl || 180, c.noRun);
  if (used.some(c => c.metrics) && (!RC.metricsAt || Date.now() - RC.metricsAt > 30000)) {
    RC.metricsAt = Date.now();
    api("/api/metrics").then(m => { RC.metrics = m; redrawPanels() }).catch(() => {});
  }
}
const stateNow = i => {
  const c = RECHECK.find(c => rcHit(c, i));
  if (!c) return null;
  if (c.metrics) return RC.metrics ? c.now(i, RC.metrics) : null;
  const t = TASK[c.task];
  return t?.status === "done" && t.result != null ? c.now(i, t.result) : null;
};
const fixedNow = i => stateNow(i)?.ok === true;
// второстепенное: сбои из истории и советы — исправлять нечего, достаточно «Понятно»
const CRASH_RE = /^(Сбоев видеодрайвера|Вылетов программ|Был единичный сбой|Разовых вылетов|Зависаний программ|Неудачных установок обновлений|Индекс стабильности)/;
const minorItem = i => i.lvl === "info" || CRASH_RE.test(i.t);
// ручная отметка «сделано» — для того, что проверить автоматически нельзя (старые сбои, починка в окне администратора)
const uMarks = id => { try { return new Set(JSON.parse(store.get("ultra.marked." + id) || "[]")) } catch { return new Set() } };
const uMarkSet = (id, set) => store.set("ultra.marked." + id, JSON.stringify([...set]));

// «с прошлой проверки»: что исправлено, что появилось, что осталось (по пунктам «что стоит сделать»)
function ultraCompare(c){
  if (!c) return "";
  const list = (arr, cls) => arr.length ? `<ul class="ucmp-list ${cls}">${arr.map(i => `<li>${esc(i.t)}</li>`).join("")}</ul>` : "";
  return `<details class="ucmp"><summary><b>С прошлой проверки</b> <span class="sub">(${esc(ago(c.prev_when))})</span>:
      <span class="ucmp-n ok">исправлено ${c.fixed.length}</span> · <span class="ucmp-n ${c.new.length ? "bad" : ""}">новое ${c.new.length}</span> · <span class="ucmp-n">осталось ${c.still.length}</span></summary>
    ${c.fixed.length ? `<div class="grp">Исправлено</div>${list(c.fixed, "fixed")}` : ""}${c.new.length ? `<div class="grp">Новое</div>${list(c.new, "new")}` : ""}
    ${c.still.length ? `<div class="grp">Осталось</div>${list(c.still, "")}` : ""}</details>`;
}
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-ultra-pdf]");
  if (!b) return;
  b.disabled = true; b.textContent = "Сохраняю…";
  try { const r = await api("/api/ultra/pdf", {}); toast("Отчёт сохранён", r.path.split("\\").pop() + " — в папке «Загрузки»") }
  catch (err) { toast("Не получилось сохранить отчёт", err.message, "bad") }
  b.disabled = false; b.textContent = "Отчёт PDF";
});

function ultraDone(j, dev){
  const st = j.stats || {}, v = j.verdict?.[0];
  const marks = uMarks(j.id);
  const marked = i => marks.has(i.t);
  const done = i => (!!i.files_done && !(i.files || []).length) || fixedNow(i) || marked(i);   // обезврежено, исправлено или отмечено
  recheckUltra([...(j.todo || []), ...(j.steps || []).flatMap(s => s.items || [])]);
  const todo = [...(j.todo || [])].sort((a, b) => Number(done(a)) - Number(done(b)));
  const left = todo.filter(i => !done(i)), fixed = todo.length - left.length;
  const leftBad = left.filter(i => ["threat", "bad"].includes(i.lvl)).length, leftWarn = left.filter(i => i.lvl === "warn").length;
  const allDone = todo.length && !left.some(i => ["threat", "bad", "warn"].includes(i.lvl));
  const icon = v === "threat" && leftBad ? ["i-bad", "!"] : v === "clean" || allDone ? ["i-ok", "✓"] : ["i-warn", "!"];
  const title = allDone && v !== "clean" ? "Всё найденное исправлено" : (j.verdict?.[1] || "Готово").split(" · ")[0];
  const stat = [st.threats ? `<span style="color:var(--bad)">угрозы: <b style="color:var(--bad)">${st.threats}</b></span>` : `<span>угроз <b>нет</b></span>`,
    `<span>осталось важного: <b>${leftBad}</b></span>`, `<span>замечаний: <b>${leftWarn}</b></span>`,
    fixed ? `<span style="color:var(--ok)">исправлено: <b style="color:var(--ok)">${fixed}</b></span>` : "",
    st.freed ? `<span>освобождено <b>${fmtB(st.freed)}</b></span>` : "", `<span>шагов: <b>${st.done ?? "?"} из ${st.steps ?? "?"}</b></span>`,
    j.finished ? `<span>заняло <b>${elapsedText(j.started, j.finished)}</b></span>` : ""].join("");
  const solvedNote = i => fixedNow(i) ? `<div class="note ok-note" style="margin-top:8px">✓ ${CRASH_RE.test(i.t) ? "Сбои были разовыми и больше не повторяются — делать ничего не нужно." : "Уже исправлено — ScanHub проверил это сейчас."}</div>`
    : marked(i) ? `<div class="note ok-note" style="margin-top:8px">✓ ${minorItem(i) ? "Принято к сведению" : "Отмечено как сделанное"}. <a data-uunmark="${esc(i.t)}">Вернуть в список</a></div>`
    : i.files_done ? `<div class="note ok-note" style="margin-top:8px">✓ Найденные файлы уже обезврежены: убраны в карантин или удалены. Вернуть из карантина можно в «Проверка на вирусы → Карантин».</div>` : "";
  const nowLine = i => { const s = stateNow(i); return s && !s.ok && s.text ? `<span class="sub now">${esc(s.text)}</span>` : "" };
  const recs = j.recs || [];
  // Malwarebytes теперь отдельная плитка среди сканеров; в старых итогах он был ссылкой
  const recTools = recs.filter(r => r.kind === "tools").map(r => ({...r, tools: r.tools.includes("malwarebytes") ? r.tools : [...r.tools, "malwarebytes"]}));
  const recOther = recs.filter(r => r.kind !== "tools" && r.t !== "Malwarebytes");
  return pnl(`<div class="head"><div class="result" style="padding:0;border:0;background:none"><div class="big"><div class="icon ${icon[0]}">${icon[1]}</div>
      <div><h3 style="margin:0">${esc(title)}</h3><div class="sub">ультра проверка ${j.status === "stopped" ? "остановлена" : "закончена"} ${esc(ago(j.finished))} · ${esc((j.finished || "").replace("T", " "))}</div></div></div></div>
      <div class="grow"></div>${j.status === "done" && !allDone ? `<button class="primary" data-fix-open="1">Исправить по шагам</button>` : ""}<button data-ultra-pdf title="Итоги в PDF — отправить другу или на форум помощи. Имя пользователя и компьютера заменяются">Отчёт PDF</button><button data-ultra-new>Новая проверка</button></div>
    ${j.status === "done" && !allDone ? `<div class="note info">Всё найденное можно исправить по шагам: что ScanHub умеет — он сделает сам по кнопке, остальное подскажет, как сделать вручную. Исправленное отмечается здесь само.</div>` : ""}
    <div class="stats big-stats">${stat}</div>
    ${ultraCompare(j.compare)}
    <h2 class="sec" style="margin:4px 0 0">Что стоит сделать</h2>
    ${todo.length ? `<div class="checks">${todo.map(i => `<div class="check${done(i) ? " solved" : ""}">${uIcon(done(i) ? "ok" : i.lvl)}
        <span><b>${esc(i.t)}</b><span class="sub">${i.s ? esc(i.s) + " · " : ""}<i>${esc(i.step)}</i></span>${done(i) ? "" : nowLine(i)}${i.files?.length ? qButtons(i.files) : ""}${solvedNote(i)}</span>
        <span class="acts">${done(i) ? "" : ultraAct(i.a, i.lvl === "threat" || i.lvl === "bad") +
          (minorItem(i) ? ` <button class="small" data-umark="${esc(i.t)}" title="Исправлять тут нечего — убрать из списка">Понятно</button>`
                        : ` <button class="small ghost" data-umark="${esc(i.t)}" title="Отметить как сделанное вручную — если ScanHub не может проверить это сам">Готово</button>`)}</span></div>`).join("")}</div>`
      : `<div class="note info">Ничего срочного — компьютер в порядке. 👍</div>`}
    <h2 class="sec" style="margin:8px 0 0">Как прошли шаги</h2>
    <ul class="steps">${(j.steps || []).map((s, i) => {
      // замечания шага — сразу на виду; то, что в порядке, — свёрнуто
      const rank = {threat: 0, bad: 1, warn: 2, info: 3};
      const items = s.items.map(x => done(x) ? {...x, lvl: "ok", a: null,
        s: fixedNow(x) ? (CRASH_RE.test(x.t) ? "разовые сбои, больше не повторяются" : "уже исправлено — проверил сейчас") : marked(x) ? (minorItem(x) ? "принято к сведению" : "отмечено как сделанное") : "найденное уже обезврежено: в карантине или удалено"} : x);
      const probs = items.filter(x => x.lvl !== "ok").sort((a, b) => (rank[a.lvl] ?? 4) - (rank[b.lvl] ?? 4));
      const fine = items.filter(x => x.lvl === "ok");
      const solved = s.status === "done" && s.items.some(done) && !probs.some(x => ["threat", "bad", "warn"].includes(x.lvl));
      return `<li>${solved ? uIcon("ok") : ultraStepIcon(s, i)}<span class="t"><b>${esc(s.title)}</b>
        ${probs.length ? ultraItems(probs, true) : ""}
        ${fine.length ? `<details class="ud"><summary class="sub">что в порядке (${fine.length})</summary>${ultraItems(fine, true)}</details>` : ""}
        ${!s.items.length ? `<span class="sub">${esc(s.hint)}</span>` : ""}</span>
        <span class="lbl">${solved ? "исправлено" : esc(s.label)}</span></li>`}).join("")}</ul>
    <h2 class="sec" style="margin:8px 0 0">Желательно сделать ещё</h2>
    <div class="sub" style="margin-top:-6px">Этого ультра проверка не может сделать сама: эти антивирусы работают только своим окном, а удаление приложений и автозагрузку лучше решать тебе.</div>
    ${recTools.map(r => `<div class="grp">${esc(r.t)}</div><div class="sub" style="margin-top:-4px">${esc(r.s)}</div>
      <div class="recs">${r.tools.map(tool).filter(Boolean).map(t => `<div class="tile"><b>${esc(t.name)}</b><p>${esc(t.simple || t.description || "")}</p><div class="row">${simpleTileButtons(t)}</div></div>`).join("")}</div>`).join("")}
    <div class="checks">${recOther.map(r => `<div class="check">${uIcon("info")}<span><b>${esc(r.t)}</b><span class="sub">${esc(r.s)}</span></span><span>${ultraAct(r.a)}</span></div>`).join("")}</div>`);
}

// ---------- данные
async function loadUltra(){
  try {
    const r = await api("/api/ultra");
    ULTRA.plan = r.plan; ULTRA.job = r.job;
    if (r.job?.status === "running") { ULTRA.setup = false; if (!ULTRA.polling) pollUltra() }
  } catch {}
  redrawPanels(); renderNav(); renderUltraCta();
}
async function pollUltra(){
  ULTRA.polling = true;
  while (true) {
    let r;
    try { r = await api("/api/ultra") } catch { await sleep(3000); continue }
    ULTRA.plan = r.plan; ULTRA.job = r.job;
    if (r.job?.status === "running") {                  // журнал проверки и её глубокой проверки — во вкладках консоли
      follow(r.job.id, true, true);
      const dj = (r.job.steps || []).find(s => s.id === "deep" && s.job)?.job;
      if (dj) follow(dj, true, true);
    }
    if (PAGE === "ultra") { const d = $("#ultraLog"); ULTRA.logOpen = d ? d.open : ULTRA.logOpen; redrawPanels() }
    renderNav(); renderUltraCta();
    if (r.job?.status !== "running") break;
    await sleep(1500);
  }
  ULTRA.polling = false;
  const j = ULTRA.job;
  if (j && ULTRA.notified !== j.id) {
    ULTRA.notified = j.id;
    toast("Ультра проверка завершена", j.verdict?.[1] || "", verdictKind(j.verdict?.[0]), 15000, () => go("ultra"));
    refresh();
    if (j.status === "done") { go("ultra"); openFix() }          // сразу — мастер исправлений по шагам
  }
}
function ultraForget(files){
  const gone = new Set((files || []).map(f => f.path));
  for (const i of [...(ULTRA.job?.todo || []), ...(ULTRA.job?.steps || []).flatMap(s => s.items)])
    if (i.files) i.files = i.files.filter(f => !gone.has(f.path));
}

// ---------- карточка на главной
function renderUltraCta(){
  const box = $("#ultraCta");
  if (!box) return;
  const j = ULTRA.job;
  let title = "Ультра проверка устройства", text = "Все проверки подряд: вирусы, мусор, здоровье, обновления, автозагрузка, приватность и сбои. В конце — итог и что стоит сделать.",
      btn = `<button class="primary" data-go-page="ultra">Начать</button>`;
  if (j?.status === "running") {
    const st = j.steps || [], cur = st.find(s => s.status === "running");
    title = "Идёт ультра проверка";
    text = cur ? `Шаг ${st.indexOf(cur) + 1} из ${st.length}: ${cur.title.toLowerCase()} · прошло ${elapsedText(j.started)}` : "Готовлюсь…";
    btn = `<button class="primary" data-go-page="ultra">Открыть</button>`;
  } else if (j) {
    text = `Последняя — ${ago(j.finished)}: ${(j.verdict?.[1] || "").toLowerCase()}.`;
    btn = j.status === "done" ? `<button data-go-page="ultra">Итоги</button><button class="primary" data-fix-open="1">Исправить по шагам</button>`
                              : `<button data-go-page="ultra">Итоги</button><button class="primary" data-ultra-new>Новая проверка</button>`;
  } else if (ULTRA.plan.length) text += ` Около ${minsText(ultraMins(ultraSel()))}.`;
  box.innerHTML = `<span class="uic plate">${icon("ultra")}</span><div class="grow"><h3>${title}</h3><p>${esc(text)}</p></div><div class="row-tools">${btn}</div>`;
}

// ---------- клики
document.addEventListener("click", async e => {
  const el = e.target.closest("[data-ultra-start],[data-ultra-new],[data-ultra-back],[data-ultra-preset],[data-ultra-deep],[data-ultra-task]");
  if (!el) return;
  if (el.hasAttribute("data-ultra-new")) { ULTRA.setup = true; if (PAGE !== "ultra") go("ultra"); else redrawPanels(); return }
  if (el.hasAttribute("data-ultra-back")) { ULTRA.setup = false; return redrawPanels() }
  if (el.dataset.ultraPreset) {
    const p = el.dataset.ultraPreset, d = ultraDefaults();
    ultraSave(p === "default" ? d : p === "none" ? {steps: [], opts: d.opts}
      : {steps: d.steps, opts: Object.fromEntries(ULTRA.plan.map(x => [x.id, (x.opts || []).map(o => o.id)]))});
    return redrawPanels();
  }
  if (el.dataset.ultraDeep) {
    DEEP = {id: el.dataset.ultraDeep, data: null}; store.set("deep", DEEP.id);
    pollDeep(); return go("scan", "deep");
  }
  if (el.dataset.ultraTask) {
    if (el.dataset.confirm && !await ask(el.dataset.confirm)) return;
    if (el.dataset.page) { const [p, s] = el.dataset.page.split(":"); go(p, s) }
    const name = el.dataset.ultraTask, t = await runTask(name, {});
    return afterTask(name, {}, t);
  }
  if (el.hasAttribute("data-ultra-start")) {
    const S = ultraSel();
    if (!S.steps.length) return;
    const uac = ultraUac(S);
    if (!await ask(`Ультра проверка займёт около ${minsText(ultraMins(S))}.` + (uac ? ` Windows ${timesText(uac)} попросит права администратора — подтверди окна UAC, иначе шаг будет ждать.` : "") +
                 " Окно можно свернуть. Начать?")) return;
    try {
      const r = await api("/api/ultra", {sel: {steps: S.steps, opts: S.opts}});
      ULTRA.setup = false;
      ULTRA.job = {id: r.id, status: "running", steps: [], started: new Date().toISOString()};
      redrawPanels(); renderNav();
      pollUltra();
    } catch (err) { toast("Не получилось начать", err.message, "err") }
  }
});
document.addEventListener("change", e => {
  const x = e.target;
  if (!x.dataset.ultraStep && !x.dataset.ultraOpt) return;
  const S = ultraSel();
  if (x.dataset.ultraStep) {
    const id = x.dataset.ultraStep;
    S.steps = x.checked ? [...new Set([...S.steps, id])] : S.steps.filter(s => s !== id);
  } else {
    const [step, opt] = x.dataset.ultraOpt.split("|"), list = new Set(S.opts[step] || []);
    x.checked ? list.add(opt) : list.delete(opt);
    S.opts[step] = [...list];
  }
  ultraSave(S); redrawPanels(); renderUltraCta();
});
setInterval(() => { if (ULTRA.job?.status === "running") { if (PAGE === "home") renderUltraCta() } }, 1000);

// ---------- итоги ультра: ручная отметка «сделано»
document.addEventListener("click", e => {
  const m = e.target.closest("[data-umark],[data-uunmark]");
  if (!m || !ULTRA.job?.id) return;
  const set = uMarks(ULTRA.job.id);
  if (m.dataset.umark) set.add(m.dataset.umark); else set.delete(m.dataset.uunmark);
  uMarkSet(ULTRA.job.id, set);
  redrawPanels();
});
