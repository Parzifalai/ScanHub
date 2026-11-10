// ============================================================ СВОДКИ ДЛЯ ВТОРОГО МНЕНИЯ ИИ
// «Скопировать сводку» в итоге проверки файла и «Сводка ПК для ИИ» (Здоровье ПК → Обзор, меню «⋯» у щита):
// сервер собирает всё, что знает ScanHub (summary.py), окно показывает текст, копирует его или сохраняет файлом в «Загрузки».
// Личное (имя учётной записи и ПК, почта) по умолчанию скрыто — галочка показывает; ключи и пароли скрыты всегда.

let LAST_CHECK_SUM = null;          // что передать серверу о последней проверке файла (заполняет renderSimpleResult)
const SUM_TITLE = {check: "Сводка проверки для ИИ", pc: "Полная сводка компьютера для ИИ", ultra: "Сводка ультра проверки для ИИ"};
const SUM_LEAD = {
  pc: "Всё, что ScanHub знает о компьютере: защита, находки, сбои, железо, диски, программы, автозагрузка, драйверы, приватность, браузеры, сеть, история проверок.",
  check: "Всё о проверке: что за файл (подпись, хэши, откуда скачан), итог ScanHub, каждый сканер с подробностями и журналом, проверенные файлы.",
  ultra: "Весь итог ультра проверки: каждый шаг и каждая находка, советы ScanHub и сведения о компьютере."};

async function sumOpen(kind, args){
  const wrap = document.createElement("div");
  wrap.className = "mdl-back";
  wrap.innerHTML = `<div class="mdl xwide sum-dlg" role="dialog" aria-modal="true" aria-labelledby="sumT">
    <div class="mdl-top"><span class="mdl-ic">✦</span><h3 id="sumT">${SUM_TITLE[kind]}</h3></div>
    <p class="sub sum-lead">${SUM_LEAD[kind]} Вставь текст в чат с ИИ (Claude, ChatGPT, Gemini) — в конце уже есть просьба: ИИ ответит коротко (в паре слов — «опасно или нет и что делать») и подробно.</p>
    <div class="sum-body"><div class="sum-wait"><div class="spin"></div><span id="sumProg">${kind === "pc" ? "Собираю данные со всего компьютера… около минуты" : "Собираю сводку…"}</span></div></div>
    <label class="switch sum-priv"><input type="checkbox" id="sumPriv" checked> Скрыть личное — имя учётной записи и компьютера, почту <span class="sub">(ключи и пароли скрыты всегда)</span></label>
    <div class="mdl-btns"><span class="sub grow" id="sumSize"></span><button type="button" data-sum-close>Закрыть</button>
      <button type="button" id="sumSave" disabled>Сохранить файлом</button><button type="button" class="primary" id="sumCopy" disabled>Скопировать</button></div></div>`;
  document.body.appendChild(wrap);
  const close = () => wrap.remove();
  wrap.addEventListener("click", e => { if (e.target === wrap || e.target.closest("[data-sum-close]")) close() });
  wrap.addEventListener("keydown", e => { if (e.key === "Escape") close() });
  const name = {pc: "pc_summary", check: "check_summary", ultra: "ultra_summary"}[kind];
  const tick = setInterval(() => { const p = TASK[name]?.progress; if (p && $("#sumProg")) $("#sumProg").textContent = progOf(p).t + (progOf(p).f != null ? ` · ${Math.round(progOf(p).f * 100)}%` : "") }, 700);
  let t;
  try { t = await runTask(name, args, true) } finally { clearInterval(tick) }
  if (!wrap.isConnected) return;
  if (t.status !== "done" || !t.result) {
    wrap.querySelector(".sum-body").innerHTML = `<div class="note bad">Не получилось собрать сводку: ${esc(t.error || "неизвестная ошибка")}</div>`;
    return;
  }
  const r = t.result, cur = () => $("#sumPriv").checked ? r.text : r.text_full;
  const show = () => {
    wrap.querySelector(".sum-body").innerHTML = `<textarea class="sum-text" readonly spellcheck="false" data-noi18n></textarea>`;
    wrap.querySelector(".sum-text").value = cur();
    $("#sumSize").textContent = `${Math.round(cur().length / 1000)} тыс. знаков` + (cur().length > 60000 ? " · если чат не принимает такой длинный текст — «Сохранить файлом» и прикрепи файл" : "");
  };
  show();
  $("#sumPriv").onchange = show;
  $("#sumCopy").disabled = $("#sumSave").disabled = false;
  $("#sumCopy").onclick = async () => {
    try { await navigator.clipboard.writeText(cur()) }
    catch { const ta = wrap.querySelector(".sum-text"); ta.select(); document.execCommand("copy") }
    toast("Сводка скопирована", "Вставь её в чат с ИИ: Ctrl+V", "ok");
    $("#sumCopy").textContent = "Скопировано ✓";
  };
  $("#sumSave").onclick = async () => {
    const s = await runTask("summary_save", {kind, private: $("#sumPriv").checked}, true);
    if (s.result?.path) toast("Сводка сохранена в «Загрузки»", s.result.path.split("\\").pop(), "ok");
    else toast("Не получилось сохранить", s.error || "", "err");
  };
  $("#sumCopy").focus();
}

document.addEventListener("click", e => {
  if (e.target.closest("[data-sum-check]")) {
    if (!LAST_CHECK_SUM) return toast("Нет проверки", "Сначала проверь файл или папку", "warn");
    return sumOpen("check", LAST_CHECK_SUM);
  }
  if (e.target.closest("[data-sum-ultra]")) return sumOpen("ultra", {});
  if (e.target.closest("[data-sum-pc]")) { $("#heroMenu") && ($("#heroMenu").hidden = true); return sumOpen("pc", {}) }
});
