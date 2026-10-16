// ============================================================ «Телефон»: проверка Android по отладке USB (сервер: phone.py)
// Пока раздел открыт и телефон не найден, окно раз в 3 с спрашивает adb, подключён ли он, — чтобы человек видел каждый шаг.

const PH = {timer: 0, steps: false};
const PH_SPECIAL = {a11y: "Спец. возможности", admin: "Администратор устройства", notif: "Доступ к уведомлениям", sms: "SMS по умолчанию", install: "Ставит другие приложения"};

function phoneStatus(){ return TASK.phone_status?.result || null }
function phoneResult(){
  const s = TASK.phone_scan;
  if (s?.status === "done" && s.result) return s.result;
  const l = TASK.phone_last?.result;
  return l && l.when ? l : null;
}
function phonePoll(){
  clearInterval(PH.timer);
  PH.timer = setInterval(async () => {
    if (PAGE !== "phone" || document.hidden) return;
    if (TASK.phone_scan?.status === "running" || TASK.phone_install?.status === "running") return;
    try { TASK.phone_status = await api("/api/task", {name: "phone_status", args: {}}); while (TASK.phone_status.status === "running") { await new Promise(r => setTimeout(r, 700)); TASK.phone_status = await api("/api/task?name=phone_status") } redrawPanels() } catch {}
  }, 3000);
}

function phoneSteps(st){
  const devs = st?.devices || [], ok = devs.find(d => d.state === "device"), unauth = devs.find(d => d.state === "unauthorized");
  const step = (n, done, title, body) => `<div class="ph-step${done ? " done" : ""}"><span class="ph-n">${done ? "✓" : n}</span><div><b>${title}</b>${body ? `<div class="sub">${body}</div>` : ""}</div></div>`;
  return `<div class="ph-steps">
    ${step(1, !!st?.adb, "Программа для связи с телефоном", st?.adb ? `Google Platform Tools готовы${st.own ? "" : " (уже стояли на компьютере)"}.`
      : `Нужны официальные Google Platform Tools (~7 МБ, с dl.google.com) — ScanHub скачает их и проверит подпись Google. <button class="small primary" data-task-run="phone_install">Скачать</button>`)}
    ${step(2, !!(ok || unauth), "Включи на телефоне отладку по USB", `<details${ok || unauth ? "" : " open"}><summary>Как включить</summary><ol class="ph-ol">
        <li>«Настройки» → «О телефоне». Семь раз подряд нажми на <b>номер сборки</b> (у Xiaomi — на «Версия ОС HyperOS» или «Версия MIUI», у Samsung — «Сведения о ПО» → «Номер сборки»). Появится «Вы стали разработчиком».</li>
        <li>Вернись в «Настройки» → «Система» (у Xiaomi — «Расширенные настройки») → <b>«Для разработчиков»</b>.</li>
        <li>Включи <b>«Отладка по USB»</b>.</li></ol>
        <div class="sub">После проверки отладку лучше выключить — ScanHub напомнит.</div></details>`)}
    ${step(3, !!ok, "Подключи телефон кабелем и разреши отладку", ok ? `Подключён: <b>${esc(ok.model || ok.serial)}</b>.`
      : unauth ? `<span style="color:var(--warn)">Телефон ждёт разрешения.</span> Разблокируй его — там окно «Разрешить отладку по USB?». Отметь «Всегда разрешать с этого компьютера» и нажми «Разрешить».`
      : `Кабель должен передавать данные (не только зарядка). Если на телефоне спросит режим USB — выбери «Передача файлов». ${st?.adb ? '<span class="ph-wait"><span class="spin"></span>жду телефон…</span>' : ""}`)}
  </div>`;
}

function pPhone(dev){
  if (PAGE === "phone" && !PH.timer) phonePoll();
  const st = phoneStatus(), r = phoneResult(), run = TASK.phone_scan?.status === "running";
  const ok = (st?.devices || []).find(d => d.state === "device");
  const btn = `<button class="${r ? "" : "primary"}" data-task-run="phone_scan" ${ok && !run ? "" : "disabled"} title="${ok ? "" : "сначала подключи телефон"}">${r ? "Проверить снова" : "Проверить телефон"}</button>`;
  const intro = explain("ScanHub подключается к телефону по кабелю через официальный инструмент Google (adb) и только читает: какие приложения стоят и откуда, кто получил опасный доступ, есть ли известные программы-следилки, давно ли были обновления безопасности. На телефон ничего не ставится. Удалить приложение или снять с него доступ можно только по кнопке — и только то, что нашла проверка.");
  const head0 = head("Проверка телефона", r ? `${esc(r.device?.name || "")} · проверено ${esc(ago(r.when))}` : "Android по кабелю, без установки чего-либо на телефон", btn);
  const busy = busyErr("phone_scan", "Проверяю телефон… не отключай кабель") + busyErr("phone_install", "Скачиваю Platform Tools…") + busyErr("phone_status", "") + busyErr("phone_uninstall", "Удаляю…") + busyErr("phone_open", "") + busyErr("phone_a11y_off", "");
  if (!r) return pnl(head0 + intro + busy + phoneSteps(st));
  const d = r.device || {};
  const vcls = r.verdict === "bad" ? "bad" : r.verdict === "warn" ? "warn" : "ok-note";
  const vtxt = r.verdict === "bad" ? "Есть серьёзные находки — разбери их ниже." : r.verdict === "warn" ? "Опасного не найдено, но есть что поправить." : "Телефон в порядке: следилок и опасного доступа не найдено.";
  const F = r.findings || [];
  const row = f => `<div class="check"><span class="ic ic-${{bad: "threat", warn: "suspicious", info: "running", ok: "clean"}[f.lvl]}">${f.lvl === "ok" ? "✓" : f.lvl === "info" ? "i" : "!"}</span>
    <span><b>${esc(f.t)}</b>${f.s ? `<span class="sub">${esc(f.s)}</span>` : ""}</span>
    <span class="acts">${f.pkg ? phoneActs(f.pkg, r) : ""}${f.lvl === "bad" || f.lvl === "warn" ? aiBtn(f.t, f.s, {source: "Телефон"}) : ""}</span></div>`;
  const order = {bad: 0, warn: 1, info: 2, ok: 3};
  const special = (r.special || []).filter(x => x.what !== "install" || x.lvl !== "info");
  const apps = r.apps || [], side = apps.filter(a => a.sideload);
  const appRow = a => `<tr><td><b class="mono">${esc(a.pkg)}</b>${a.stalker ? ` ${sevChip(["bad", "следилка: " + a.stalker])}` : ""}${a.vt?.known ? ` ${sevChip(a.vt.mal >= 3 ? ["bad", `VirusTotal ${a.vt.mal}/${a.vt.total}`] : a.vt.mal || a.vt.sus ? ["warn", `VirusTotal ${a.vt.mal + a.vt.sus}/${a.vt.total}`] : ["ok", `VirusTotal: чисто`])}` : a.vt && !a.vt.error ? ` ${sevChip(["info", "VirusTotal не знает"])}` : ""}
      ${a.perms?.length ? `<div class="sub">доступ: ${esc(a.perms.join(", "))}</div>` : ""}</td>
    <td class="sub">${esc(a.source)}${a.installed ? `<br>${esc(a.installed.slice(0, 10))}` : ""}</td><td class="acts">${phoneActs(a.pkg, r)}</td></tr>`;
  return pnl(`${head0}${busy}
    <div class="ph-dev"><div><b>${esc(d.name || "Телефон")}</b><div class="sub">Android ${esc(d.android)}${d.skin ? " · " + esc(d.skin) : ""} · патч безопасности ${esc(d.patch || "?")}</div></div>
      ${r.battery?.level != null ? `<div class="ph-kv"><span class="sub">Батарея</span><b>${r.battery.level}%</b><span class="sub">${esc(r.battery.health || "")}${r.battery.temp ? ` · ${r.battery.temp}°C` : ""}${r.battery.cycles ? ` · ${r.battery.cycles} циклов` : ""}</span></div>` : ""}
      ${r.storage ? `<div class="ph-kv"><span class="sub">Память</span><b>${r.storage.pct}%</b><span class="sub">${fmtB(r.storage.used)} из ${fmtB(r.storage.total)}</span></div>` : ""}
      <div class="ph-kv"><span class="sub">Приложений</span><b>${r.counts?.apps ?? apps.length}</b><span class="sub">не из магазина: ${r.counts?.sideload ?? side.length}</span></div></div>
    <div class="note ${vcls}"><b>${vtxt}</b>${r.ioc_n ? ` Сверено со списком из ${r.ioc_n} известных приложений-следилок.` : ""}${r.vt ? "" : " Добавь ключ VirusTotal в ⚙ Настройках — тогда приложения не из магазина будут сверяться и с антивирусами."}</div>
    <div class="checks">${F.slice().sort((a, b) => order[a.lvl] - order[b.lvl]).map(row).join("")}</div>
    ${special.length ? `<details class="dsec"${special.some(x => x.lvl !== "info") ? " open" : ""}><summary class="grp">Кто получил особый доступ · ${special.length}</summary>
      <div class="sub" style="margin:2px 0 6px">Такой доступ нужен немногим приложениям: менеджерам паролей, антивирусам, лаунчерам. Если видишь незнакомое — сними доступ или удали.</div>
      <table class="t small">${special.map(x => `<tr><td>${sevChip(x.lvl === "bad" ? ["bad", "Опасно"] : x.lvl === "warn" ? ["warn", "Проверь"] : ["ok", "Обычно норм"])}</td><td><b class="mono">${esc(x.pkg)}</b>${x.system ? ' <span class="sub-inline">системное</span>' : x.sideload ? ' <span class="sub-inline">не из магазина</span>' : ""}<div class="sub">${esc(PH_SPECIAL[x.what] || x.t)}: ${esc(x.s)}</div></td>
        <td class="acts">${x.what === "a11y" && !x.system ? `<button class="small" data-ph-a11y="${esc(x.pkg)}">Снять доступ</button>` : ""}${x.system ? "" : phoneActs(x.pkg, r)}</td></tr>`).join("")}</table></details>` : ""}
    ${side.length ? `<details class="dsec"${side.some(a => a.stalker || a.vt?.mal) ? " open" : ""}><summary class="grp">Установлено не из магазина · ${side.length}</summary>
      <div class="sub" style="margin:2px 0 6px">Эти приложения поставлены из APK-файла (скачаны в браузере, присланы в мессенджере) — их никто не проверял. Если что-то незнакомо — удали.</div>
      <table class="t small">${side.map(appRow).join("")}</table></details>` : ""}
    <details class="dsec"><summary class="grp">Все приложения · ${apps.length}</summary><table class="t small">${apps.map(appRow).join("")}</table></details>
    <div class="sub" style="margin-top:10px">Закончил? Выключи «Отладку по USB» в настройках для разработчиков и отключи кабель. ScanHub сам закроет связь с телефоном через полторы минуты.</div>`);
}
function phoneActs(pkg, r){
  return `<button class="small" data-ph-open="${esc(pkg)}" title="Откроет страницу приложения в настройках телефона — там видно название, разрешения и кнопки «Удалить», «Остановить»">На телефоне</button>`
    + `<button class="small danger" data-ph-del="${esc(pkg)}">Удалить</button>`;
}

document.addEventListener("click", async e => {
  const t = e.target.closest("[data-ph-open],[data-ph-del],[data-ph-a11y]");
  if (!t) return;
  e.preventDefault();
  if (t.dataset.phOpen) { await runTask("phone_open", {pkg: t.dataset.phOpen}); if (TASK.phone_open?.status === "done") toast("Открыл на телефоне", "смотри экран телефона: там страница этого приложения"); return }
  if (t.dataset.phA11y) {
    if (!await ask(`Снять у ${t.dataset.phA11y} доступ к спец. возможностям? Приложение перестанет видеть экран и нажимать за тебя. Если это нужное приложение (менеджер паролей, лаунчер) — включишь обратно в настройках телефона.`, {ok: "Снять доступ"})) return;
    await runTask("phone_a11y_off", {pkg: t.dataset.phA11y}); if (TASK.phone_a11y_off?.status === "done") runTask("phone_scan"); return;
  }
  if (t.dataset.phDel) {
    if (!await ask(`Удалить ${t.dataset.phDel} с телефона? Приложение и его данные будут удалены. Вернуть можно, только поставив его заново.`, {ok: "Удалить", danger: true})) return;
    await runTask("phone_uninstall", {pkg: t.dataset.phDel}); if (TASK.phone_uninstall?.status === "done") runTask("phone_scan");
  }
});
