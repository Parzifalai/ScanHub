// ============================================================ МАСТЕР ИСПРАВЛЕНИЙ после ультра проверки
let FIX = {open: false, min: false, plan: null, i: 0, st: {}, sel: {}, loading: false};
const FIX_IC = {done: ["clean", "✓"], skip: ["skipped", "–"], error: ["error", "!"], running: ["running", ""]};
const FIX_LVL = {threat: ["threat", "!"], bad: ["threat", "!"], warn: ["suspicious", "!"], info: ["pending", "i"]};
const fixKey = () => "fix." + (FIX.plan?.source || "");
function fixLoadState(){
  try { const s = JSON.parse(store.get(fixKey()) || "null"); FIX.st = s?.st || {}; FIX.i = s?.i || 0 } catch { FIX.st = {}; FIX.i = 0 }
}
const fixSave = () => store.set(fixKey(), JSON.stringify({st: FIX.st, i: FIX.i}));

async function openFix(force){
  FIX.open = true; FIX.min = false;
  const src = ULTRA.job?.id;
  if (!force && FIX.plan && FIX.plan.source === src) return fixRender();
  if (!force) {
    try {                                              // уже собранный список для этой проверки — сразу
      const t = await api("/api/task?name=fixplan");
      if (t.status === "done" && t.result?.source === src) { FIX.plan = t.result; fixLoadState(); return fixRender() }
    } catch {}
  }
  FIX.plan = null; FIX.loading = true; fixRender();
  const tick = setInterval(fixRender, 1000);
  const t = await runTask("fixplan", {}, true);
  clearInterval(tick);
  FIX.loading = false;
  if (t.status === "error") { FIX.err = t.error; return fixRender() }
  FIX.plan = t.result; FIX.err = null; fixLoadState();
  FIX.sel = {};
  for (const k in FIX.st) { delete FIX.st[k].items; delete FIX.st[k].title }     // список собран заново — старые остатки не нужны
  fixSave();
  fixRender();
}
function fixClose(min){ FIX.open = false; FIX.min = !!min; fixRender() }

// после действия список шага пересчитывается: сделанное исчезает, у оставшегося — свежие размеры (хранится в FIX.st)
const itemsOf = c => FIX.st[c.id]?.items || c.items || [];
const titleOf = c => FIX.st[c.id]?.title || c.title;
function fixSel(c){
  if (!FIX.sel[c.id]) FIX.sel[c.id] = new Set(itemsOf(c).filter(x => x.on).map(x => x.id));
  return FIX.sel[c.id];
}
function fixStatusIcon(c, i){
  const s = FIX.st[c.id]?.status;
  if (s === "running") return `<span class="ic ic-running"><div class="spin"></div></span>`;
  const [cls, t] = FIX_IC[s] || FIX_LVL[c.lvl] || FIX_LVL.info;
  return `<span class="ic ic-${cls}">${t}</span>`;
}

function fixCardHtml(c){
  const st = FIX.st[c.id] || {};
  const busy = st.status === "running";
  const head = `<div class="fc-head"><span class="fc-grp">${esc(c.group)}</span>
      ${c.kind === "manual" ? `<span class="badge-manual">Нужно сделать самому</span>` : c.kind === "scanners" ? `<span class="badge-manual">Последний этап</span>` : `<span class="badge-auto">ScanHub сделает сам</span>`}</div>
    <h3>${esc(titleOf(c))}</h3><p>${esc(c.text)}</p>
    ${c.list?.length ? `<ul class="fc-list">${c.list.slice(0, 15).map(x => `<li>${esc(x)}</li>`).join("")}${c.list.length > 15 ? `<li class="sub">…и ещё ${c.list.length - 15}</li>` : ""}</ul>` : ""}`;
  let body = "";
  if (c.kind === "auto") {
    body = `<div class="row-tools"><button class="primary" data-fix-do ${busy ? "disabled" : ""}>${esc(c.do.label)}${c.do.uac ? " 🛡" : ""}</button>
      ${c.open ? ultraAct(c.open) : ""}</div>`;
  } else if (c.kind === "choice" && !itemsOf(c).length) {
    body = `<div class="note ok-note"><b>✓ Здесь всё сделано.</b> Можно переходить дальше.</div>${c.open ? `<div class="row-tools">${ultraAct(c.open)}</div>` : ""}`;
  } else if (c.kind === "choice") {
    const S = fixSel(c), items = itemsOf(c);
    const needUac = c.apply.uac || (c.apply.uac_if && items.some(x => S.has(x.id) && x.admin));
    body = `<div class="rows">${items.map(x => `<label class="crow"><input type="checkbox" data-fix-item="${esc(x.id)}" ${S.has(x.id) ? "checked" : ""} ${busy ? "disabled" : ""}>
        <span><b>${esc(x.label)}</b>${x.admin ? " " + adminChip : ""}${x.sub ? `<span class="sub">${esc(x.sub)}</span>` : ""}</span><span>${c.id === "quarantine" ? `<button class="small" type="button" data-file-why="${esc(x.value?.path || x.id)}">Почему?</button>` : ""}</span></label>`).join("")}</div>
      <div class="row-tools"><button class="primary" data-fix-do ${busy || !S.size ? "disabled" : ""}>${esc(c.apply.label)} (${S.size})${needUac ? " 🛡" : ""}</button>
        <button data-fix-all="1" ${busy ? "disabled" : ""}>Отметить все</button><button data-fix-all="0" ${busy ? "disabled" : ""}>Снять все</button>
        ${c.open ? ultraAct(c.open) : ""}</div>`;
  } else if (c.kind === "manual") {
    body = `<div class="fc-how"><b>Что сделать:</b><ol>${(c.how || []).map(x => `<li>${esc(x)}</li>`).join("")}</ol>${c.why ? `<div class="sub">${esc(c.why)}</div>` : ""}</div>
      <div class="row-tools">${c.open ? ultraAct(c.open, true) : ""}<button data-fix-mark="done" ${busy ? "disabled" : ""}>${st.notyet ? "Проверить ещё раз" : "Я сделал"}</button>
        ${st.notyet ? `<button data-fix-mark="done" data-force="1">Всё равно отметить</button>` : ""}</div>`;
  } else if (c.kind === "scanners") {
    body = `<div class="recs">${(c.tools || []).map(tool).filter(Boolean).map(t => `<div class="tile"><b>${esc(t.name)}</b><p>${esc(t.simple || t.description || "")}</p><div class="row">${simpleTileButtons(t)}</div></div>`).join("")}</div>
      <div class="row-tools">${c.link ? ultraAct(c.link) : ""}<button class="primary" data-fix-mark="done">Готово — всё проверил</button></div>`;
  }
  const res = st.msg ? `<div class="note ${st.status === "error" ? "bad" : st.warn ? "warn" : "info"}">${st.status === "done" ? "✓ " : ""}${esc(st.msg)}</div>` : "";
  const uacWait = busy && st.uac ? `<div class="note warn"><b>Подтверди окно UAC.</b> Windows спрашивает разрешение администратора. В окне будет написано «Python» — это ScanHub (он написан на Python), окно открылось из-за этого шага.</div>` : "";
  return `${head}${body}${c.note ? `<div class="sub fc-note">${esc(c.note)}</div>` : ""}${uacWait}
    ${busy ? `<div class="sub busy" style="display:flex;gap:8px;align-items:center"><div class="spin" style="width:16px;height:16px;border-width:2px"></div>Выполняю…</div>` : ""}${res}`;
}

function fixRender(){
  let box = $("#fixw");
  if (!box) { box = document.createElement("div"); box.id = "fixw"; document.body.appendChild(box) }
  renderFixPill();
  if (!FIX.open) { box.hidden = true; return }
  box.hidden = false;
  if (!FIX.plan) {
    box.innerHTML = `<div class="fixw-back"><div class="fixw"><div class="fixw-head"><b>Исправление после ультра проверки</b><div class="grow"></div><button class="small" data-fix-close>✕</button></div>
      <div class="fixw-wait">${FIX.err ? `<div class="note bad">${esc(FIX.err)}</div><button class="primary" data-fix-reload>Попробовать снова</button>` :
        `<div class="spin"></div><b>Готовлю список исправлений…</b><div class="sub">Перепроверяю всё, что можно исправить, — с момента проверки что-то могло измениться. 1–2 минуты (дольше всего — список устаревших программ).</div>
         <div class="sub mono">${esc(TASK.fixplan?.progress || "")}</div>`}</div></div></div>`;
    return;
  }
  const cards = FIX.plan.cards;
  FIX.i = Math.max(0, Math.min(FIX.i, cards.length - 1));
  const c = cards[FIX.i];
  const done = cards.filter(x => ["done", "skip"].includes(FIX.st[x.id]?.status)).length;
  const groups = [...new Set(cards.map(x => x.group))];
  const scroll = box.querySelector(".fixw-card")?.scrollTop || 0, lscroll = box.querySelector(".fixw-list")?.scrollTop || 0;
  box.innerHTML = `<div class="fixw-back"><div class="fixw" role="dialog" aria-label="Исправление после ультра проверки">
    <div class="fixw-head"><div><b>Исправление после ультра проверки</b><div class="sub">шаг ${FIX.i + 1} из ${cards.length} · сделано или пропущено: ${done}
      ${FIX.plan.finished ? ` · проверка от ${esc(FIX.plan.finished.replace("T", " ").slice(0, 16))}` : ""}</div></div><div class="grow"></div>
      ${FIX.auto ? "" : '<button class="small primary" data-fix-auto title="ScanHub сам пройдёт все шаги, которые умеет">▶ Пройти автоматически</button>'}
      <button class="small" data-fix-reload title="Собрать список заново" ${FIX.auto ? "disabled" : ""}>Обновить</button><button class="small" data-fix-close title="Закрыть — продолжить можно потом">✕</button></div>
    <div class="progress" title="${Math.round(done / cards.length * 100)}%"><div style="width:${done / cards.length * 100}%"></div></div>
    <div class="fixw-auto">${FIX.auto ? `<div class="spin"></div><span>${FIX.auto.stop ? "Остановлю после текущего шага…" : `Автопрохождение: шаг ${FIX.auto.k} из ${FIX.auto.n} — ${esc(titleOf(c))}`}</span>
      <div class="grow" style="flex:1"></div>${FIX.auto.stop ? "" : '<button class="small" data-fix-auto-stop>Остановить</button>'}` : ""}</div>
    <div class="fixw-body">
      <nav class="fixw-list">${groups.map(g => `<div class="fl-grp">${esc(g)}</div>${cards.map((x, i) => x.group !== g ? "" :
        `<button class="fl-item${i === FIX.i ? " on" : ""}" data-fix-go="${i}">${fixStatusIcon(x, i)}<span>${esc(titleOf(x))}</span></button>`).join("")}`).join("")}</nav>
      <section class="fixw-card">${fixCardHtml(c)}</section>
    </div>
    <div class="fixw-foot"><button data-fix-step="-1" ${FIX.i ? "" : "disabled"}>← Назад</button><div class="grow"></div>
      ${FIX.st[c.id]?.status === "done" ? "" : `<button data-fix-mark="skip">Пропустить</button>`}
      ${FIX.i < cards.length - 1 ? `<button class="${FIX.st[c.id]?.status === "done" ? "primary" : ""}" data-fix-step="1">Дальше →</button>` : `<button class="primary" data-fix-close>Закончить</button>`}</div>
  </div></div>`;
  const cs = box.querySelector(".fixw-card"), ls = box.querySelector(".fixw-list");
  if (cs) cs.scrollTop = scroll;
  if (ls) ls.scrollTop = lscroll;
}
function renderFixPill(){
  let p = $("#fixpill");
  const show = !FIX.open && FIX.min && FIX.plan;
  if (!show) { if (p) p.remove(); return }
  if (!p) { p = document.createElement("button"); p.id = "fixpill"; p.className = "primary fixpill"; document.body.appendChild(p) }
  const cards = FIX.plan.cards, done = cards.filter(x => ["done", "skip"].includes(FIX.st[x.id]?.status)).length;
  p.innerHTML = `↩ Вернуться к исправлению · ${done} из ${cards.length}`;
  p.dataset.fixOpen = "1";
}

function fixMsg(name, r){
  r = r || {};
  const errs = r.errors?.length ? ` Не получилось: ${r.errors.slice(0, 2).join("; ")}` : "";
  return ({
    junk_clean: () => `Освобождено ${fmtB(r.freed || 0)}.${r.skipped ? ` Занятых файлов пропущено: ${r.skipped}.` : ""}${errs}`,
    quarantine: () => `В карантине: ${r.moved}. Вернуть можно в «Проверка на вирусы → Карантин».${errs}`,
    privacy_apply: () => "Настройки применены. Часть вступит в силу после перезапуска Проводника или входа в Windows.",
    firewall_set: () => "Правила выключены. Включить обратно — «Приватность → Брандмауэр».",
    envpath_fix: () => "PATH очищен. Открытые терминалы увидят изменения после перезапуска.",
    appx_remove: () => `Удалено приложений: ${r.removed?.length || 0}.${r.errors?.length ? ` Не удалось: ${r.errors.length}.` : ""}`,
    restore_enable: () => r.status?.enabled ? `Защита системы включена.${r.point?.status === "ok" ? " Первая точка восстановления создана." : ""}` : "Защита не включилась.",
    hosts_set: () => `Блокировка включена: доменов в списке ${r.domains || "—"}.`,
    force_remove_many: () => `Убрано записей: ${r.removed || 0}. Копии сохранены в папке резервных копий ScanHub.${r.failed?.length ? ` Не получилось: ${r.failed.join(", ")}.` : ""}`,
    trim: () => `TRIM выполнен: ${(r.ok || []).join(", ") || "—"}.`,
  }[name] || (() => "Готово."))();
}

// очистка: пересчитать размеры заново — удалённое исчезает, у занятого (браузер, Telegram открыты) остаётся остаток
async function junkDone(r, items, done){
  const s = (await runTask("junk_scan", {}, true)).result || {};
  const cats = Object.fromEntries((s.categories || []).map(x => [x.id, x]));
  const MIN = 20 * 2 ** 20;
  const rest = items.map(x => {
    if (x.id === "recycle") return s.recycle?.size ? {...x, on: false, sub: `${fmtB(s.recycle.size)} · удаляется навсегда — сначала загляни в неё`} : null;
    const c = cats[x.id];
    if (!c || (c.size || 0) < MIN) return null;
    const was = x.size || 0, left = c.size;
    const why = !was ? `${fmtB(left)}` :
      left > was * 1.3 ? `${fmtB(left)} — выросло: сейчас сюда что-то скачивается${x.id === "wu" ? " (Windows Update качает обновления — пусть докачает и установит)" : ""}` :
      left >= was * 0.6 ? `${fmtB(left)} осталось — это файлы моложе суток (их ScanHub не трогает) или занятые открытой программой` :
      `${fmtB(left)} осталось`;
    return {...x, size: left, on: false, sub: why + (c.desc ? " · " + c.desc : "")};
  }).filter(Boolean);
  const title = s.c_total ? `Освободить место на C: (сейчас свободно ${fmtB(s.c_free)}, ${Math.round(s.c_free / s.c_total * 100)}%)` : null;
  const busy = r.skipped ? " Часть не удалилась: свежие файлы (моложе суток) ScanHub не трогает, а занятые открытыми программами (браузер, Telegram, игры) удалятся, если закрыть их и нажать ещё раз." : "";
  done({msg: `Освобождено ${fmtB(r.freed || 0)}.${busy}${r.errors?.length ? " Не получилось: " + r.errors.slice(0, 2).join("; ") : ""}`, warn: !!r.errors?.length}, rest, title);
}

// ---------- «Пройти автоматически»: всё, что ScanHub умеет сам, — подряд, с тем, что отмечено по умолчанию
const AUTO_SKIP = {quarantine: "что убрать в карантин, решаешь ты",
  sfc: "окно на 15–30 минут и перезагрузка — запусти сам, когда будет время"};
function autoPlan(){
  const run = [], manual = [], skip = [];
  for (const c of FIX.plan.cards) {
    if (["done", "skip"].includes(FIX.st[c.id]?.status)) continue;
    if (c.kind === "manual" || c.kind === "scanners") { manual.push(c); continue }
    let why = AUTO_SKIP[c.id];
    if (c.id === "restore" && /мало места/.test(c.note || "")) why = "на C: мало места — точки восстановления займут ещё до 5% диска";
    if (!why && c.kind === "choice" && !itemsOf(c).some(x => fixSel(c).has(x.id))) why = "по умолчанию ничего не отмечено — реши сам";
    if (why) skip.push([c, why]); else run.push(c);
  }
  run.sort((a, b) => (a.id === "winget") - (b.id === "winget"));      // обновления программ — последними
  const uac = run.filter(c => c.id === "winget" || c.do?.uac || c.apply?.uac ||
                             (c.apply?.uac_if && itemsOf(c).some(x => fixSel(c).has(x.id) && x.admin))).length;
  return {run, manual, skip, uac};
}
async function fixAuto(){
  const p = autoPlan();
  if (!p.run.length) return say("Автоматически делать нечего: остались шаги, где нужно твоё решение или действие.", "Всё, что можно, уже сделано");
  const go = await modal({title: `Пройти автоматически ${p.run.length} ${p.run.length === 1 ? "шаг" : p.run.length < 5 ? "шага" : "шагов"}?`,
    body: "ScanHub сделает их сам по очереди — с тем, что отмечено по умолчанию." +
          (p.uac ? ` Windows ${p.uac} ${p.uac === 1 ? "раз" : p.uac < 5 ? "раза" : "раз"} попросит права администратора — подтверждай окна UAC, иначе шаг будет ждать.` : "") +
          " Где нужно твоё решение — пропущу и покажу в конце.",
    list: p.run.map(titleOf), ok: "Начать", cancel: "Отмена", icon: "▶"});
  if (!go) return;
  FIX.auto = {stop: false, k: 0, n: p.run.length};
  for (const c of p.run) {
    if (FIX.auto.stop) break;
    FIX.auto.k++;
    FIX.i = FIX.plan.cards.indexOf(c);
    fixRender();
    await fixApply(true);
  }
  const stopped = FIX.auto.stop;
  FIX.auto = null;
  const left = FIX.plan.cards.filter(c => !["done", "skip"].includes(FIX.st[c.id]?.status));
  if (left.length) FIX.i = FIX.plan.cards.indexOf(left[0]);
  fixSave(); fixRender();
  const ok = p.run.filter(c => FIX.st[c.id]?.status === "done").length, bad = p.run.filter(c => FIX.st[c.id]?.status === "error");
  modal({title: stopped ? "Автопрохождение остановлено" : "Готово: ScanHub прошёл всё, что умеет сам",
    body: `Сделано: ${ok}${bad.length ? `, не получилось: ${bad.length} (${bad.map(titleOf).join(", ")})` : ""}.` +
          (left.length ? ` Осталось решить или сделать самому: ${left.length} — список слева, открываю первый.` : " Ничего не осталось."),
    list: p.skip.map(([c, w]) => `${titleOf(c)} — ${w}`).concat(p.manual.map(c => `${titleOf(c)} — ${c.kind === "scanners" ? "последний этап, запусти сканеры сам" : "нужно сделать самому"}`)),
    ok: "Понятно", cancel: null, icon: "✓"});
}

async function fixApply(auto){
  const ask = auto ? async () => true : window.ask;               // в автопрохождении уже подтверждено одним окном
  const c = FIX.plan.cards[FIX.i];
  const prev = FIX.st[c.id] || {};
  const set = (o) => { FIX.st[c.id] = {items: prev.items, title: prev.title, ...o}; fixSave(); fixRender() };
  const done = (o, rest, title) => {           // шаг выполнен: оставить в списке только то, что ещё не сделано
    if (rest) { FIX.sel[c.id] = new Set(rest.filter(x => x.on).map(x => x.id)); o.items = rest }
    if (title) o.title = title;
    set({status: "done", ...o});
  };
  try {
    if (c.kind === "auto") {
      const a = c.do;
      if (a.confirm && !await ask(a.confirm)) return;
      set({status: "running", uac: !!a.uac});
      if (a.launch) {
        await api("/api/launch", {what: a.launch});
        return set({status: "done", msg: "Открыто в отдельном окне — следуй инструкциям в нём и не закрывай его до конца."});
      }
      const t = await runTask(a.task, a.args || {}, true);
      if (t.status === "error") throw new Error(t.error);
      afterTask(a.task, a.args || {}, t);
      return set({status: "done", msg: fixMsg(a.task, t.result), warn: !!t.result?.errors?.length});
    }
    if (c.kind === "choice") {
      const S = fixSel(c), ap = c.apply, items = itemsOf(c);
      const picked = items.filter(x => S.has(x.id)), vals = picked.map(x => x.value);
      const unpicked = items.filter(x => !S.has(x.id));
      if (!vals.length) return;
      if (ap.confirm && !await ask(ap.confirm)) return;
      set({status: "running", uac: !!(ap.uac || (ap.uac_if && picked.some(x => x.admin)))});
      if (ap.updates) {
        const id = await startUpdates(vals);
        if (!id) throw new Error("обновление не началось");
        return done({msg: `Обновление началось (${vals.length}): скачиваю, проверяю на вирусы и ставлю по очереди. Ход — по кнопке «Ход обновления».`}, unpicked);
      }
      if (ap.launch_each) {
        for (const v of vals) await api("/api/launch", {what: ap.launch_each + v});
        return done({msg: `Открыто окон установки: ${vals.length}. Дождись, пока каждое закончит работу.`}, unpicked);
      }
      if (ap.each) {
        const bad = [], failed = [];
        for (const x of picked) {
          const args = {...(ap.args || {}), [ap.each]: x.value}, t = await runTask(ap.task, args, true);
          if (t.status === "error") { bad.push(t.error); failed.push(x) } else afterTask(ap.task, args, t);
        }
        if (bad.length === vals.length) throw new Error(bad[0]);
        return done({msg: `Готово: ${vals.length - bad.length} из ${vals.length}.${bad.length ? " Не получилось: " + bad[0] : ""}`, warn: !!bad.length}, [...failed, ...unpicked]);
      }
      const args = {...(ap.args || {}), [ap.arg]: ap.flatten ? vals.flat() : vals};
      const t = await runTask(ap.task, args, true);
      if (t.status === "error") throw new Error(t.error);
      afterTask(ap.task, args, t);
      const r = t.result || {};
      if (ap.task === "junk_clean") return junkDone(r, items, done);
      // что не получилось (например, файл занят) — остаётся в списке, остальное выбранное исчезает
      const failedIds = new Set(picked.filter(x => (r.errors || []).some(e => String(e).includes(String(x.label)) || String(e).includes(String(x.id)))).map(x => x.id));
      return done({msg: fixMsg(ap.task, r), warn: !!r.errors?.length}, items.filter(x => !S.has(x.id) || failedIds.has(x.id)));
    }
  } catch (e) {
    set({status: "error", msg: "Не получилось: " + e.message});
  }
}

document.addEventListener("click", e => {
  const el = e.target.closest("[data-fix-auto],[data-fix-auto-stop],[data-fix-open],[data-fix-close],[data-fix-reload],[data-fix-go],[data-fix-step],[data-fix-mark],[data-fix-do],[data-fix-all],#fixw [data-go-page],#fixw [data-ultra-deep]");
  if (!el) return;
  if (el.hasAttribute("data-fix-auto")) return FIX.auto ? null : fixAuto();
  if (el.hasAttribute("data-fix-auto-stop")) { if (FIX.auto) FIX.auto.stop = true; return fixRender() }
  if (FIX.auto && el.closest("#fixw") && !el.hasAttribute("data-fix-close")) return;     // пока идёт автопрохождение — шаги не трогаем
  if (el.dataset.fixOpen) return openFix();
  if (el.hasAttribute("data-fix-close")) return fixClose(true);
  if (el.hasAttribute("data-fix-reload")) return openFix(true);
  if (el.dataset.goPage || el.dataset.ultraDeep) { fixClose(true); return }      // раздел приложения — мастер сворачивается в кнопку
  if (el.dataset.fixGo) { FIX.i = +el.dataset.fixGo; fixSave(); return fixRender() }
  if (el.dataset.fixStep) { FIX.i += +el.dataset.fixStep; fixSave(); return fixRender() }
  const c = FIX.plan?.cards[FIX.i];
  if (!c) return;
  if (el.dataset.fixMark === "done" && c.kind === "manual" && !el.dataset.force) return fixCheckDone(c);
  if (el.dataset.fixMark) {
    FIX.st[c.id] = {status: el.dataset.fixMark, msg: el.dataset.fixMark === "done" && c.kind === "manual" ? "Отмечено как сделанное." : ""};
    if (el.dataset.fixMark === "skip" && FIX.i < FIX.plan.cards.length - 1) FIX.i++;
    fixSave(); return fixRender();
  }
  if (el.hasAttribute("data-fix-do")) return fixApply();
  if (el.dataset.fixAll) {
    FIX.sel[c.id] = new Set(el.dataset.fixAll === "1" ? itemsOf(c).map(x => x.id) : []);
    return fixRender();
  }
});
document.addEventListener("change", e => {
  const x = e.target;
  if (!x.dataset.fixItem) return;
  const c = FIX.plan.cards[FIX.i], S = fixSel(c);
  x.checked ? S.add(x.dataset.fixItem) : S.delete(x.dataset.fixItem);
  fixRender();
});
document.addEventListener("keydown", e => { if (e.key === "Escape" && FIX.open) fixClose(true) });

// ---------- «Я сделал»: ScanHub перепроверяет, правда ли сделано (где это можно проверить)
const FIX_VERIFY = [
  {when: c => c.id.startsWith("security_"), task: "security",
   ok: (c, r) => { const it = (Array.isArray(r) ? r : r?.items || []).find(x => x.id === c.id.slice(9)); return it ? {ok: it.ok === true, text: "защита всё ещё выключена"} : null }},
  {when: c => c.id === "wu_drivers", task: "driver_updates", ok: (c, r) => Array.isArray(r) ? {ok: !r.length, text: `Windows Update всё ещё предлагает драйверов: ${r.length}`} : null},
  {when: c => c.id === "restore", task: "restore", ok: (c, r) => ({ok: !!r?.enabled, text: "защита системы (точки восстановления) всё ещё выключена"})},
];
async function fixCheckDone(c){
  const t = c.todo || titleOf(c);
  const v = FIX_VERIFY.find(v => v.when(c));
  const rc = !v && typeof RECHECK !== "undefined" ? RECHECK.find(r => rcHit(r, {t})) : null;
  let res = null;
  if (v || (rc && !rc.noRun)) {
    FIX.st[c.id] = {status: "running", msg: ""}; fixRender();
    try {
      if (rc?.metrics) { RC.metrics = await api("/api/metrics"); res = rc.now({t}, RC.metrics) }
      else {
        const task = v ? v.task : rc.task;
        if (task) { const r = await runTask(task, undefined, true); if (r.status === "done") res = v ? v.ok(c, r.result) : rc.now({t}, r.result) }
      }
    } catch {}
  }
  if (res && res.ok === false) {
    FIX.st[c.id] = {notyet: true, warn: true, msg: `Проверил — похоже, ещё не сделано${res.text ? ": " + res.text : ""}. Сделай шаги выше и нажми «Проверить ещё раз». Если уверен, что сделал, — «Всё равно отметить».`};
  } else {
    FIX.st[c.id] = {status: "done", msg: res?.ok ? "Проверил — сделано." : "Отмечено как сделанное. Проверить это автоматически ScanHub не может."};
  }
  fixSave(); fixRender();
}

// ---------- «Почему?» у подозрительного файла: кто из антивирусов что нашёл, подпись, откуда скачан
async function showFileWhy(path){
  toast("Смотрю, почему файл подозрительный…", path.split("\\").pop(), "info", 2500);
  const t = await runTask("file_why", {path}, true);
  if (t.status !== "done") return toast("Не получилось", t.error || "", "bad");
  const r = t.result || {}, vt = r["онлайн"]?.VirusTotal, ci = r["онлайн"]?.CIRCL, dl = r["скачан_из_интернета"];
  const row = (k, v) => v ? `<tr><td class="sub">${esc(k)}</td><td>${v}</td></tr>` : "";
  const vtHtml = vt && typeof vt === "object"
    ? `<b>${esc(vt["вредоносным_считают"])}</b> антивирусов считают вредоносным${vt["метка"] ? ` · метка: ${esc(vt["метка"])}` : ""}
       ${(vt["кто_нашёл"] || []).length ? `<ul class="fc-list">${vt["кто_нашёл"].map(x => `<li class="mono">${esc(x)}</li>`).join("")}</ul>` : ""}`
    : esc(typeof vt === "string" ? vt : "нет данных");
  const few = vt && typeof vt === "object" && /^([12]) из/.test(vt["вредоносным_считают"] || "");
  const html = `<table class="t small kv">${row("Файл", `<span class="mono">${esc(r["путь"] || path)}</span>`)}${row("Размер", esc(r["размер"]))}
      ${row("Цифровая подпись", esc([r["подпись"], r["подписал"]].filter(Boolean).join(" — ")))}${row("Программа", esc([r["продукт"], r["компания"], r["версия"]].filter(Boolean).join(" · ")))}
      ${row("Откуда скачан", dl && typeof dl === "object" ? esc([dl["сайт"], dl["страница"] ? "со страницы " + dl["страница"] : ""].filter(Boolean).join(" ")) : esc(dl || ""))}
      ${row("VirusTotal", vtHtml)}${row("CIRCL", ci && typeof ci === "object" ? (ci["известный_оригинальный_файл"] ? "известный оригинальный файл — не подменён" : "") : esc(ci || ""))}</table>
    ${few ? `<div class="note info">Тревогу подняли 1–2 антивируса — чаще всего это ложная тревога эвристики. Но если файл скачан не с официального сайта программы, лучше удалить его и скачать заново с официального.</div>` : ""}
    <div class="row-tools">${aiBtn(`Подозрительный файл ${path.split("\\").pop()}`, JSON.stringify(r).slice(0, 1500), {source: "Почему файл подозрительный"})}</div>`;
  modal({title: "Почему файл подозрительный", html, ok: "Закрыть", cancel: null, icon: "!", wide: true});
}
document.addEventListener("click", e => {
  const b = e.target.closest("[data-file-why]");
  if (!b) return;
  e.preventDefault(); e.stopPropagation();
  showFileWhy(b.dataset.fileWhy);
}, true);
