const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

// ---------- ход задачи: «37% · текст» (так пишет сервер) или «… 3 из 10 …» → доля; «осталось» — по скорости с начала
function progOf(text){
  const s = String(text || "");
  let m = s.match(/^(\d{1,3})% · /);
  if (m) return {f: Math.min(1, +m[1] / 100), t: s.slice(m[0].length)};
  m = s.match(/(\d+) из (\d+)/);                      // «файл 3 из 10» — третий ещё идёт, поэтому 2,5 из 10
  if (m && +m[2] > 1) return {f: Math.min(1, Math.max(0, +m[1] - 0.5) / +m[2]), t: s};
  m = s.match(/(?:скачиваю|загружаю|распаковываю)\D{0,12}(\d{1,3})%/);
  if (m) return {f: +m[1] / 100, t: s};
  return {f: null, t: s};
}
function etaText(started, f){
  if (!started || !(f >= 0.04) || f >= 1) return "";
  const el = (Date.now() - new Date(started)) / 1000;
  if (!(el >= 8)) return "";
  const left = el * (1 - f) / f;
  return left < 50 ? "осталось меньше минуты" : left < 5400 ? `осталось ~${Math.max(1, Math.round(left / 60))} мин` : `осталось ~${Math.round(left / 3600)} ч`;
}
const progBar = (f, extra = "") => `<div class="progx"><div class="progress"><div style="width:${Math.max(2, Math.round(f * 100))}%"></div></div><span class="mono">${Math.round(f * 100)}%${extra ? " · " + extra : ""}</span></div>`;
function progHtml(text, started){
  const p = progOf(text);
  return p.f == null ? "" : progBar(p.f, etaText(started, p.f));
}
const store = { get(k){ try { return localStorage.getItem("scanhub."+k) } catch { return null } },
                set(k,v){ try { localStorage.setItem("scanhub."+k, v) } catch {} } };
let TOOLS = [], LAST = null, CFG = {}, HISTORY = [], active = null, openJobs = [], batches = {}, simpleBatch = null;
let MODE = store.get("mode") || "simple";
const multiSel = new Set(JSON.parse(store.get("multi") || "null") || []);
const SECTIONS = [
  ["scanners", "Проверка файлов", "запускаются прямо здесь, вывод — в консоли"],
  ["online", "Онлайн-проверка", "нужен бесплатный API-ключ (⚙ Настройки)"],
  ["downloadable", "Антивирусы-сканеры", "открываются своим окном, обычно с правами администратора"],
  ["research", "Исследование системы", "для разбора подозрительных процессов"],
];
const ORDER = {threat:0, suspicious:1, error:2, unknown:3, clean:4, launched:5};

// ============================================================ окна подтверждения в стиле ScanHub (вместо confirm/alert браузера)
const DANGER = /удал|уничтож|карантин|безвозврат|заверш|навсегда|остановить|выключить|отправить в корзину/i;
function modal({title, body = "", ok = "Продолжить", cancel = "Отмена", danger = false, icon = "?", copy = null, list = null, html = "", wide = false, buttons = true}){
  return new Promise(resolve => {
    const prev = document.activeElement;
    const wrap = document.createElement("div");
    wrap.className = "mdl-back";
    wrap.innerHTML = `<div class="mdl${danger ? " danger" : ""}${wide ? " xwide" : ""}" role="alertdialog" aria-modal="true" aria-labelledby="mdlT">
      <div class="mdl-top"><span class="mdl-ic">${esc(icon)}</span><h3 id="mdlT">${esc(title)}</h3></div>
      ${body ? `<p>${esc(body)}</p>` : ""}${list?.length ? `<ul class="mdl-list">${list.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}${copy != null ? `<textarea readonly rows="8" spellcheck="false">${esc(copy)}</textarea>` : ""}${html ? `<div class="mdl-html">${html}</div>` : ""}
      ${buttons ? `<div class="mdl-btns">${cancel ? `<button data-mdl="0">${esc(cancel)}</button>` : ""}<button class="${danger ? "danger-fill" : "primary"}" data-mdl="1">${esc(ok)}</button></div>` : ""}</div>`;
    const close = v => {
      document.removeEventListener("keydown", key, true);
      wrap.classList.add("out");
      setTimeout(() => wrap.remove(), 140);
      prev?.focus?.();
      resolve(v);
    };
    const key = e => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(false) }
      if (e.key === "Enter" && document.activeElement?.dataset?.mdl) { e.preventDefault(); e.stopPropagation(); close(document.activeElement.dataset.mdl === "1") }
      if (e.key === "Tab") {                           // фокус не уходит из окна
        const b = [...wrap.querySelectorAll("button,textarea")], i = b.indexOf(document.activeElement);
        e.preventDefault(); b[(i + (e.shiftKey ? -1 : 1) + b.length) % b.length].focus();
      }
    };
    wrap.addEventListener("click", e => {
      const b = e.target.closest("[data-mdl]");
      if (b) close(b.dataset.mdl === "1");
      else if (e.target === wrap) close(false);
    });
    document.addEventListener("keydown", key, true);
    document.body.appendChild(wrap);
    // у опасных действий по умолчанию выбрана «Отмена»: случайный Enter ничего не удалит
    (wrap.querySelector(danger && cancel ? '[data-mdl="0"]' : '[data-mdl="1"]') || wrap.querySelector("button")).focus();
    const ta = wrap.querySelector("textarea"); if (ta) { ta.focus(); ta.select() }
  });
}
// «Убрать файлы в карантин? Программы перестанут работать.» → заголовок — вопрос, текст — остальное, кнопка — глагол из вопроса
function splitQuestion(text){
  const s = String(text).trim().split(/(?<=[.?!»])\s+(?=[А-ЯЁA-Z«(0-9])/);
  const qi = s.findIndex(x => x.trim().endsWith("?"));
  let title, body;
  if (qi === 0) { title = s[0]; body = s.slice(1).join(" ") }
  else if (qi > 0 && s[qi].length <= 14) { title = s[0]; body = s.slice(1, qi).join(" ") }     // «…займёт 15 минут. Начать?» → кнопка «Начать»
  else { title = s[0]; body = s.slice(1).join(" ") }
  const q = s[qi >= 0 ? qi : 0] || "";
  const verb = (q.match(/^([А-ЯЁ][а-яё]+(?:ть|ти)(?:ся)?)(?=[\s,?]|$)/) || [])[1];     // \b в JS не понимает кириллицу
  return {title, body, verb};
}
function ask(text, opts = {}){
  const {title, body, verb} = splitQuestion(text);
  const danger = opts.danger ?? DANGER.test(text);
  return modal({title, body, ok: opts.ok || verb || "Да", cancel: opts.cancel || "Отмена", danger, icon: danger ? "!" : "?"});
}
function say(text, title){
  const t = title ? {title, body: text} : splitQuestion(text);
  return modal({title: t.title, body: t.body, ok: "Понятно", cancel: null, icon: "i"});
}

async function api(path, body){
  const r = await fetch(path, body === undefined ? {headers:{"X-Token":TOKEN}} :
    {method:"POST", headers:{"X-Token":TOKEN,"Content-Type":"application/json"}, body:JSON.stringify(body)});
  const j = await r.json();
  if (r.status === 403 && j.error === "bad token") { location.reload(); throw new Error("перезагружаю окно…") }
  if (!r.ok) { const e = new Error(j.error || r.statusText); e.api = true; throw e }
  return j;
}
function ago(iso){
  if (!iso) return "никогда";
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 90) return "только что";
  if (s < 3600) return Math.round(s/60) + " мин назад";
  if (s < 86400) return Math.round(s/3600) + " ч назад";
  return Math.round(s/86400) + " дн назад";
}
const tool = id => TOOLS.find(t => t.id === id);
const isService = t => t.source.type === "service";

// ============================================================ общий статус инструмента
function status(t){
  const s = t.state || {};
  if (t.busy) return ["b-info", t.busy];
  if (s.blocked) return ["b-bad", "Заблокирован антивирусом"];
  if (t.missing) return ["b-warn", "Нужен " + t.missing.map(m => m.label).join(", ")];
  if (t.source.type === "system") return t.ready ? ["b-ok","Встроенный"] : ["b-bad","Не найден"];
  if (isService(t)) return t.source.nokey ? ["b-ok","Без ключа"] : t.ready ? ["b-ok","Ключ есть"] : ["b-muted","Нужен API-ключ"];
  if (!t.ready) return t.source.type === "manual" ? ["b-muted","Не скачан"] : ["b-muted","Не установлен"];
  if (t.stale) return ["b-warn", `Базы устарели (${t.age_days} дн)`];
  if (t.data_missing) return ["b-warn", "Нужно скачать базы"];
  if (t.update_available) return ["b-warn","Есть обновление"];
  return ["b-ok","Готов"];
}

// ============================================================ значки (вместо эмодзи: одна толщина линии, цвет текста)
const ICONS = {
  home: '<path d="M3 11 12 4l9 7"/><path d="M5 9.5V20h14V9.5"/><path d="M10 20v-6h4v6"/>',
  ultra: '<circle cx="4.8" cy="18.8" r="2.3"/><path d="M7.1 18.8h8.4a3.15 3.15 0 0 0 0-6.3h-7a3.15 3.15 0 0 1 0-6.3h6.3"/><path d="M17.8 10.5V2.6"/><path d="M17.8 3h4l-1.3 2 1.3 2h-4"/>',
  scan: '<path d="M12 3 5 6v6c0 4.4 3 8 7 9 4-1 7-4.6 7-9V6z"/><path d="m9 12 2 2 4-4"/>',
  deep: '<path d="M12 3 5 6v6c0 4.4 3 8 7 9 4-1 7-4.6 7-9V6z"/><circle cx="11.5" cy="11" r="2.6"/><path d="m13.5 13 2.2 2.2"/>',
  clean: '<path d="m19.5 3.5-7 8"/><path d="M9.5 10.5l4 4"/><path d="M9.5 10.5C6.5 11 4.5 14 3.5 20.5c6.5-1 9.5-3 10-6"/><path d="M7 17.5l2-2"/>',
  disk: '<path d="M20.5 13A8.5 8.5 0 1 1 11 3.5V13z"/><path d="M14.5 3.6a8.5 8.5 0 0 1 5.9 5.9h-5.9z"/>',
  apps: '<path d="M20.5 7.8 12 3.3 3.5 7.8v8.4l8.5 4.5 8.5-4.5z"/><path d="M3.5 7.8 12 12.3l8.5-4.5M12 12.3v8.4"/>',
  speed: '<path d="M4.6 18.5a9 9 0 1 1 14.8 0"/><path d="m12 13.5 4.2-5"/><circle cx="12" cy="13.5" r="1.4"/>',
  privacy: '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2.5"/>',
  health: '<path d="M21.5 12h-4l-3 8-5-16-3 8h-4"/>',
  phone: '<rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M10.5 18.5h3"/><path d="m9.5 10 2 2 3.5-3.5"/>',
  res: '<path d="M4 4v16h16"/><path d="m7.5 15 3.5-4 3 2.5 5-6.5"/>',
  tools: '<path d="M4 6.5h9M17 6.5h3M4 12h3M11 12h9M4 17.5h11M19 17.5h1"/><circle cx="15" cy="6.5" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="17.5" r="2"/>',
  history: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  file: '<path d="M14 3.5H6.5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V8z"/><path d="M14 3.5V8h4.5"/>',
  folder: '<path d="M3.5 6.5a1 1 0 0 1 1-1h4.8l2 2h8.2a1 1 0 0 1 1 1v9.5a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1z"/>',
  quick: '<path d="M13 2.5 4.5 14h7l-1 7.5L19 10h-7z"/>',
  fps: '<rect x="3" y="4.5" width="18" height="13" rx="2"/><path d="M7 14.5v-6h3M7 11.5h2.5M12.5 14.5v-6h2a1.5 1.5 0 0 1 0 3h-2"/><path d="M9 21h6M12 17.5V21"/>',
  game: '<path d="M7.5 7h9a4.5 4.5 0 0 1 4.4 5.4l-.9 4.2a2.2 2.2 0 0 1-3.8 1L14.5 15.5h-5l-1.7 2.1a2.2 2.2 0 0 1-3.8-1l-.9-4.2A4.5 4.5 0 0 1 7.5 7z"/><path d="M8 10v3M6.5 11.5h3"/><circle cx="15.5" cy="10.8" r=".7"/><circle cx="17.3" cy="12.6" r=".7"/>',
  chip: '<rect x="6.5" y="6.5" width="11" height="11" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5" rx=".5"/><path d="M9.5 3v3.5M14.5 3v3.5M9.5 17.5V21M14.5 17.5V21M3 9.5h3.5M3 14.5h3.5M17.5 9.5H21M17.5 14.5H21"/>',
  fan: '<circle cx="12" cy="12" r="1.8"/><path d="M12 10.2c-1.4-3.8-.6-6.9 2.4-7 2.6-.1 3.3 3 .9 5"/><path d="M13.6 12.9c3.9 1 6.1 3.4 4.7 6-1.2 2.2-4.2 1.3-4.4-1.8"/><path d="M10.3 12.9c-2.7 3-5.8 3.8-7.1 1.3-1.2-2.3 1.2-4.3 3.9-3.1"/>',
  power: '<path d="M12 3v8"/><path d="M6.6 6.6a8 8 0 1 0 10.8 0"/>',
  net: '<path d="M2.5 9a14 14 0 0 1 19 0"/><path d="M5.5 12.5a9.5 9.5 0 0 1 13 0"/><path d="M8.7 16a5 5 0 0 1 6.6 0"/><circle cx="12" cy="19.3" r="1.1" fill="currentColor"/>',
  idea: '<path d="M9 18h6M10 21h4"/><path d="M12 3a6 6 0 0 0-3.6 10.8c.6.5 1 1.3 1 2.1V16h5.2v-.1c0-.8.4-1.6 1-2.1A6 6 0 0 0 12 3z"/>',
  bug: '<rect x="8" y="7" width="8" height="12" rx="4"/><path d="M9.5 7.5 8 5M14.5 7.5 16 5M8 11H4.5M19.5 11H16M8 15.5l-3 1.5M16 15.5l3 1.5M12 10v9"/>',
  gear: '<circle cx="12" cy="12" r="2.8"/><path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7"/><circle cx="12" cy="12" r="6.3"/>',
};
const icon = (name, cls = "") => ICONS[name] ? `<svg class="svg-ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>` : "";
document.querySelectorAll("[data-ic]").forEach(el => { el.innerHTML = icon(el.dataset.ic) });

// ============================================================ ПРОСТОЙ РЕЖИМ
function renderHero(){
  const d = tool("defender"), sys = d?.system;
  let kind = "ok", title = "Компьютер под защитой", text = "Встроенный антивирус Windows работает, базы свежие.";
  if (!sys) { kind = "warn"; title = "Проверяю защиту…"; text = "" }
  else if (sys.realtime === false) { kind = "bad"; title = "Защита выключена"; text = "Защита в реальном времени Microsoft Defender отключена. Включи её в «Безопасность Windows» → «Защита от вирусов и угроз»." }
  else if ((Date.now() - new Date(sys.updated)) / 864e5 > 3) { kind = "warn"; title = "Базы антивируса устарели"; text = `Последнее обновление — ${ago(sys.updated)}.` }
  const last = HISTORY.find(h => h.batch || h.tool === "defender");
  if (last && kind === "ok") text += ` Последняя проверка: ${ago(last.started)} — ${last.verdict?.[1]?.toLowerCase() || "готово"}.`;
  const color = {ok:"var(--ok)", warn:"var(--warn)", bad:"var(--bad)"}[kind];
  const mark = {ok:'<path d="m22 33 7 7 13-14" stroke="#fff" stroke-width="5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
                warn:'<path d="M32 18v16M32 42v1" stroke="#fff" stroke-width="5" stroke-linecap="round"/>',
                bad:'<path d="m24 24 16 16M40 24 24 40" stroke="#fff" stroke-width="5" stroke-linecap="round"/>'}[kind];
  $("#hero").innerHTML = `<svg class="shield" viewBox="0 0 64 64"><path d="M32 4 8 14v16c0 15 10.2 26.8 24 30 13.8-3.2 24-15 24-30V14z" fill="${color}"/>${mark}</svg>
    <div><h2>${title}</h2><p>${esc(text)}</p>
    ${kind === "warn" && sys ? `<p style="margin-top:8px"><button class="small" data-run="defender" data-mode="sigupdate">Обновить базы</button></p>` : ""}</div>`;
}

function simpleTileButtons(t){
  const s = t.state || {};
  if (t.busy) return `<span class="sub">${esc(t.busy)}…</span>`;
  if (s.blocked) return `<span class="note bad" style="flex-basis:100%">Защитник Windows не даёт скачать эту программу. Подробности — в режиме «Разработчик».</span>`;
  if (t.source.type === "manual" && !t.ready) return `<button class="primary small" data-link="${esc(t.source.page)}">Скачать с сайта</button><button class="small" data-install="${t.id}">Я скачал — найти</button>`;
  if (t.source.type === "system" && !t.ready) return t.source.page ? `<button class="primary small" data-link="${esc(t.source.page)}">Скачать с сайта</button>` : `<span class="sub">не установлен</span>`;
  if (!t.ready) return `<button class="primary small" data-install="${t.id}">Скачать</button>`;
  const runMode = t.modes.find(m => m.id === (t.simple_mode || (t.id === "minersearch" ? "full" : t.modes[0].id)));
  const fresh = t.source.type === "manual" ? `<button class="small" data-link="${esc(t.source.page)}">Скачать свежий</button><button class="small" data-install="${t.id}">Найти</button>`
                                           : `<button class="small" data-update="${t.id}">Обновить</button>`;
  if (t.stale || t.update_available) return `<button class="primary small" data-run="${t.id}" data-mode="${runMode.id}">Запустить</button>${fresh}
     <span class="sub" style="flex-basis:100%">${t.stale ? "Встроенные базы старые — лучше сначала обновить." : "Есть новая версия."}</span>`;
  return `<button class="primary small" data-run="${t.id}" data-mode="${runMode.id}">Запустить</button>`;
}

// ---------- другие антивирусы: спокойный список вместо витрины. Не реклама: без «самых сильных», без ярких кнопок,
// по делу — что ищет и как работает; когда находок нет — свёрнуто и помечено «необязательно».
const REC_INFO = {
  cureit:      {who: "Dr.Web",     g: "virus", what: "вирусы и трояны",                     how: "без установки · бесплатно для дома"},
  kvrt:        {who: "Kaspersky",  g: "virus", what: "вирусы, трояны, руткиты",             how: "без установки · бесплатно"},
  eset:        {who: "ESET",       g: "virus", what: "вирусы и нежелательные программы",    how: "разово, потом удаляет себя · бесплатно"},
  emsisoft:    {who: "Emsisoft",   g: "virus", what: "трояны, шпионы, руткиты",             how: "без установки · бесплатно"},
  msert:       {who: "Microsoft",  g: "virus", what: "то же, что Defender, на свежих базах", how: "без установки · бесплатно"},
  malwarebytes:{who: "Malwarebytes", g: "virus", what: "вредоносы и рекламные программы",   how: "ставится как программа"},
  minersearch: {who: "открытый код", g: "miner", what: "скрытые майнеры",                   how: "без установки · бесплатно"},
  adwcleaner:  {who: "Malwarebytes", g: "adware", what: "реклама, тулбары, угонщики браузера", how: "без установки · бесплатно"},
};
const REC_GROUPS = [["virus", "Второе мнение по вирусам", ""],
                    ["miner", "Если компьютер шумит и греется без причины", ""],
                    ["adware", "Если в браузере реклама, чужая стартовая страница или поиск", ""]];
function recsHtml(ids, {threat = false, title = "", extra = ""} = {}){
  // Malwarebytes ставится как программа — советуем, только если он уже стоит
  const list = ids.map(tool).filter(t => t && (t.id !== "malwarebytes" || t.ready));
  if (!list.length && !extra) return "";
  const btns = t => simpleTileButtons(t).replace(/class="primary small"/g, 'class="small"');
  const body = REC_GROUPS.map(([g, name, sub]) => {
    const ts = list.filter(t => (REC_INFO[t.id]?.g || "virus") === g);
    if (!ts.length) return "";
    return `<div class="rec-g"><div class="rec-gh">${esc(name)}</div>${sub ? `<div class="sub">${esc(sub)}</div>` : ""}
      ${ts.map(t => { const i = REC_INFO[t.id] || {}; return `<div class="rec-row"><span><b>${esc(t.name)}</b>${i.who ? ` <span class="sub-inline">${esc(i.who)}</span>` : ""}
        <span class="sub">ищет: ${esc(i.what || t.simple || "")} · ${esc(i.how || "")}</span></span><span class="row">${btns(t)}</span></div>` }).join("")}</div>`;
  }).join("") + extra;
  const note = `<div class="sub rec-note">ScanHub не связан с этими компаниями и ничего не получает за эти советы. Все сканеры — бесплатные, ScanHub скачивает их только с официальных сайтов и проверяет подпись.</div>`;
  const head = title || (threat ? "Есть находки — перепроверь дополнительными сканерами" : "Чтобы быть максимально уверенным в чистоте ПК — заверши проверку дополнительными сканерами");
  const lead = threat ? "Разные антивирусы ловят разное: если два-три из них тоже что-то найдут — это точно стоит убрать, а если нет — находка, скорее всего, ложная."
    : "ScanHub уже проверил компьютер своими движками. Каждый сканер ниже ищет по собственным базам и даёт второе мнение — достаточно одного-двух. Бесплатно, 10–20 минут.";
  return `<div class="recs-box${threat ? " threat" : ""}"><div class="recs-h">${esc(head)}</div><div class="sub" style="margin:2px 0 6px">${esc(lead)}</div>${body}${note}</div>`;
}

// HiJackThis+: подробный отчёт о точках перехвата системы — разбирает его помощник
function hjtTile(){
  const t = tool("hijackthis");
  if (!t) return "";
  const last = HISTORY.find(h => h.tool === "hijackthis" && h.mode_label && /отч/i.test(h.mode_label) && h.verdict?.[0] === "launched");
  return `<div class="tile"><b>${esc(t.name)} — отчёт о системе</b><p>Показывает всё нестандартное в автозагрузке, браузерах, службах и сетевых настройках — там, где прячутся вирусы и рекламное ПО. Сам ничего не удаляет; отчёт разберёт помощник.</p>
    <div class="row">${t.ready ? `<button class="${last ? "" : "primary "}small" data-run="hijackthis" data-mode="log" title="Попросит права администратора — в окне будет «Python», это ScanHub">Создать отчёт</button>` : simpleTileButtons(t)}
      ${last ? `<button class="primary small" data-ai-ask="Разбери мой последний отчёт HiJackThis+: что в нём подозрительного и что с этим делать?">✦ Разобрать отчёт</button>` : ""}</div>
    ${last ? `<span class="sub">последний отчёт: ${esc(ago(last.started))}</span>` : ""}</div>`;
}

const IN_DEEP = new Set(["minersearch"]);
function renderSimple(){
  renderHero();
  // MinerSearch и так запускается внутри глубокой и ультра проверки — второй раз вручную его не предлагаем
  $("#sTiles").innerHTML = TOOLS.filter(t => t.section === "downloadable" && !IN_DEEP.has(t.id)).map(t => `
    <div class="tile"><b>${esc(t.name)}</b><p>${esc(t.simple || t.description)}</p>
      <div class="row">${simpleTileButtons(t)}</div></div>`).join("") + hjtTile();
  const online = TOOLS.filter(t => t.section === "online");
  const on = online.filter(t => t.ready && !t.source.nokey);
  $("#sOnline").innerHTML = online.length ? `<div class="tile" style="flex-direction:row;align-items:center;gap:14px;flex-wrap:wrap">
      <div style="flex:1;min-width:min(240px,100%)"><b>Онлайн-проверка в 70+ антивирусах</b>
      <p>${on.length ? `Подключено: ${on.map(t => esc(t.name)).join(", ")}. При проверке файла в интернет уходит только его «отпечаток» (хэш), сам файл остаётся у тебя.`
                     : "Бесплатно подключи VirusTotal: тогда каждый проверяемый файл будет дополнительно сверяться с базой 70+ антивирусов."}</p></div>
      ${on.length ? "" : `<button class="primary" id="openSettings2">Подключить</button>`}</div>` : "";
  const items = HISTORY.slice(0, 6);
  $("#sRecent").innerHTML = items.length ? items.map(h => `<div><span class="dot ${h.verdict?.[0]||""}"></span>
      <span class="t">${esc(h.tool_name)} — ${esc(h.target ? h.target.split("\\").pop() || h.target : h.mode_label)}</span>
      <span>${esc(h.verdict?.[1]||"")}</span><span class="sub">${ago(h.started)}</span></div>`).join("")
    : `<div><span class="sub">Пока ни одной проверки</span></div>`;
  renderSimpleResult();
}

function verdictOf(rows){
  const done = rows.filter(r => r.status !== "running");
  const vs = done.map(r => r.verdict?.[0]).filter(v => v && v !== "launched");
  return vs.sort((a,b) => ORDER[a]-ORDER[b])[0];
}
async function simpleScan(kind){
  const r = await api("/api/pick", {kind});
  if (!r.path) return;
  return simpleScanPath(r.path, kind);
}
async function simpleScanPath(path, kind){
  const tools = TOOLS.filter(t => t.ready && !t.data_missing && t.modes.some(m => m.multi));
  const batch = await scanBatch(path, tools, {kind});
  simpleBatch = batch; renderSimpleResult();
  if (PAGE !== "scan" || SUB !== "check") go("scan", "check");
  $("#sResult")?.scrollIntoView({block: "start", behavior: "smooth"});
}
$("#sFile").onclick = () => simpleScan("file");
$("#sFolder").onclick = () => simpleScan("folder");
$("#sQuick").onclick = async () => {
  const batch = Math.random().toString(36).slice(2, 10);
  batches[batch] = {target: "", jobs: [], quick: true};
  const id = await run("defender", "quick", null, batch, true);
  if (id) batches[batch].jobs.push(id);
  simpleBatch = batch; renderSimpleResult();
};

// ============================================================ РЕЖИМ РАЗРАБОТЧИКА
function devCard(t){
  const s = t.state || {}, [cls, txt] = status(t), sys = t.system, src = t.source;
  const meta = [];
  if (src.type === "system") {
    if (sys) meta.push(`движок <b>${esc(sys.version)}</b>`, `базы <b>${esc(sys.signatures)}</b>`, `обновлены ${ago(sys.updated)}`);
  } else if (!isService(t)) {
    if (s.installed) meta.push(`${src.type === "github-release" || src.type === "github-source" ? "версия" : src.type === "builtin" ? "правила от" : "файл от"} <b>${esc(s.installed)}</b>`);
    if (s.rules) meta.push(`правил <b>${s.rules}</b>`);
    if (s.latest && s.latest !== s.installed) meta.push(`последняя <b>${esc(s.latest)}</b>`);
    if (s.installed) meta.push(s.verified ? "✓ " + esc(s.verified) : "⚠ сумма/подпись не проверены");
  }
  const notes = [];
  if (s.blocked) notes.push(`<div class="note bad"><b>Defender заблокировал загрузку:</b> ${esc(s.blocked)}.
      Возможно ложное срабатывание, но решать тебе. Если доверяешь — добавь исключение для <code>D:\\ScanHub\\apps</code> в «Безопасность Windows» сам и нажми «Установить» снова. <a data-dismiss="${t.id}">скрыть</a></div>`);
  if (s.error) notes.push(`<div class="note bad">${esc(s.error)} <a data-dismiss="${t.id}">скрыть</a></div>`);
  if (s.check_error) notes.push(`<div class="note warn">Не удалось проверить обновления: ${esc(s.check_error)}</div>`);
  if (t.missing) notes.push(...t.missing.map(m => `<div class="note warn">Нужен ${esc(m.label)}: <a data-link="${esc(m.url)}">скачать</a></div>`));
  if (sys && sys.realtime === false) notes.push(`<div class="note warn">Защита в реальном времени выключена</div>`);
  if (isService(t) && !t.ready) notes.push(`<div class="note info">Получи бесплатный ключ: <a data-link="${esc(src.signup)}">регистрация</a> → <a data-link="${esc(src.key_page)}">страница ключа</a>, затем вставь его в <a data-settings>⚙ Настройки</a>.</div>`);
  if (s.held && Object.keys(s.held).length) notes.push(`<div class="note warn"><b>Придержаны версии:</b><br>${Object.values(s.held).map(esc).join("<br>")}
      <div class="sub" style="margin-top:4px">Стоит предыдущая, проверенная версия. Обычно в следующем релизе это исправляют, и ScanHub обновится сам.</div>
      <a data-force-install="${t.id}">Установить новую всё равно</a></div>`);
  if (t.data_missing) notes.push(`<div class="note warn">${esc(t.needs_data.label)} (~250 МБ, один раз): <button class="small" data-run="${t.id}" data-mode="${esc(t.needs_data.mode)}">Скачать базы</button></div>`);
  if (t.stale) notes.push(`<div class="note warn">Встроенным базам ${t.age_days} дн. Перед проверкой лучше скачать свежую версию.</div>`);

  let actions = "";
  if (src.type === "manual") {
    actions = `<button class="${t.ready ? "" : "primary "}small" data-link="${esc(src.page)}">${t.ready ? "Скачать свежий" : "Скачать с сайта Dr.Web"}</button>
               <button class="small" data-install="${t.id}" ${t.busy?"disabled":""}>${t.ready ? "Найти снова" : "Найти скачанный"}</button>`;
  } else if (!["system","service"].includes(src.type)) {
    if (!t.ready && !t.missing) actions = `<button class="primary small" data-install="${t.id}" ${t.busy?"disabled":""}>Установить${src.type === "direct" ? " (скачать)" : ""}</button>`;
    else if (t.update_available || t.stale) actions = `<button class="primary small" data-update="${t.id}" ${t.busy?"disabled":""}>Обновить${s.latest && s.latest !== s.installed ? " до " + esc(s.latest) : ""}</button>`;
  }
  const modes = t.ready ? t.modes.map(m => (m.target === "text" || m.target === "url")
      ? `<div class="textmode"><input type="text" id="tx-${t.id}-${m.id}" placeholder="${esc(m.placeholder||"")}" spellcheck="false"><button class="small" data-run="${t.id}" data-mode="${m.id}">${esc(m.label)}</button></div>`
      : `<button class="small${m.upload ? " danger" : ""}" data-run="${t.id}" data-mode="${m.id}" title="${m.target==="path"||m.target==="file"?"по пути из строки сверху":""}">${esc(m.label)}${m.target==="path"||m.target==="file"?" ↑":""}${m.gui||m.console?" ↗":""}${m.admin||(m.gui&&t.admin)?" 🛡":""}</button>`).join("") : "";
  const link = t.repo ? `<a data-link="https://github.com/${esc(t.repo)}">${esc(t.repo)}</a>` : (t.homepage ? `<a data-link="${esc(t.homepage)}">${esc(new URL(t.homepage).host)}</a>` : "");
  const auto = ["system","service","manual"].includes(src.type) || (src.type === "builtin" && src.builtin !== "yara") ? `<span>${src.type === "system" ? "обновляется Windows" : src.type === "manual" ? "обновление — вручную с сайта" : src.type === "builtin" ? "встроено в ScanHub" : "онлайн-сервис"}</span>` :
      `<label class="switch"><input type="checkbox" data-auto="${t.id}" ${t.auto_update?"checked":""}> Автообновление</label>`;

  const det = [];
  if (t.exe_path && t.exe_path !== "service") det.push(["exe", t.exe_path]);
  if (s.path && !isService(t)) det.push(["папка", s.path]);
  if (s.installed_at) det.push(["установлен", s.installed_at.replace("T"," ")]);
  if (s.checked_at) det.push(["проверка обновлений", s.checked_at.replace("T"," ")]);
  if (src.asset) det.push(["шаблон ассета", src.asset]);
  if (src.url) det.push(["url", src.url]);
  if (src.signer) det.push(["подписант", src.signer]);
  for (const m of t.modes) det.push([`режим ${m.id}`, isService(t) ? `${src.service}.${m.action}(${m.target})` : [t.exe ? t.exe : "{exe}", ...(m.cmd || m.args || [])].join(" ") + (m.gui ? "  [GUI]" : m.console ? "  [консоль]" : "")]);
  const codes = {...(t.exit_codes||{})};
  if (Object.keys(codes).length) det.push(["коды выхода", Object.entries(codes).map(([k,v]) => `${k}=${v[1]}`).join(", ")]);
  const manifest = Object.fromEntries(Object.entries(t).filter(([k]) => !["state","ready","exe_path","busy","system","update_available","auto_update","age_days","stale","missing"].includes(k)));

  return `<div class="card">
    <div class="top"><div><h3>${esc(t.name)}</h3><div class="cat">${esc(t.category||"")}</div></div>
      <span class="badge ${cls}">${esc(txt)}</span></div>
    <div class="desc">${esc(t.description||"")}</div>
    ${meta.length ? `<div class="meta">${meta.map(x=>`<span>${x}</span>`).join("")}</div>` : ""}
    ${notes.join("")}
    ${actions || modes ? `<div class="modes">${actions}${modes}</div>` : ""}
    <details><summary>Подробности</summary>
      <table>${det.map(([k,v]) => `<tr><td>${esc(k)}</td><td class="m">${esc(v)}</td></tr>`).join("")}</table>
      ${s.latest_notes ? `<p style="margin:10px 0 4px">Что нового в ${esc(s.latest)}:</p><pre>${esc(s.latest_notes)}</pre>` : ""}
      <p style="margin:10px 0 4px">Манифест:</p><pre>${esc(JSON.stringify(manifest, null, 2))}</pre>
    </details>
    <div class="foot">${link}${auto}</div>
  </div>`;
}

function renderDev(){
  $("#lastCheck").textContent = "обновления: " + ago(LAST);
  const multi = TOOLS.filter(t => t.modes.some(m => m.multi));
  if (!multiSel.size) multi.forEach(t => multiSel.add(t.id));
  $("#multiTools").innerHTML = multi.map(t => `
    <label class="chip" style="${t.ready?"":"opacity:.55"}" title="${t.ready ? "" : status(t)[1]}">
      <input type="checkbox" data-multi="${t.id}" ${multiSel.has(t.id)?"checked":""} ${t.ready?"":"disabled"}> ${esc(t.name)}
    </label>`).join("");
  const open = new Set([...document.querySelectorAll("#sections details[open]")].map(d => d.closest(".card")?.dataset.id));
  const typed = Object.fromEntries([...document.querySelectorAll("#sections input[id^=tx-]")].map(i => [i.id, i.value]));
  queueMicrotask(() => Object.entries(typed).forEach(([id, v]) => { const i = document.getElementById(id); if (i) i.value = v }));
  $("#sections").innerHTML = SECTIONS.map(([id, title, hint]) => {
    const list = TOOLS.filter(t => t.section === id);
    return list.length ? `<div class="section-h"><h2>${title}</h2><span class="sub">${hint}</span></div>
      <div class="grid">${list.map(t => devCard(t).replace('<div class="card">', `<div class="card" data-id="${t.id}">`)).join("")}</div>` : "";
  }).join("");
  open.forEach(id => { const d = document.querySelector(`.card[data-id="${id}"] details`); if (d) d.open = true });
}

// ============================================================ общее
function render(){
  document.querySelectorAll("[data-mode-set]").forEach(b => b.classList.toggle("on", b.dataset.modeSet === MODE));
  document.querySelectorAll(".dev-only").forEach(e => e.hidden = MODE !== "dev");
  renderSimple();
  if (typeof PAGE !== "undefined") {
    renderNav();
    if (PAGE === "tools") renderDev(); else $("#lastCheck").textContent = "обновления: " + ago(LAST);
    if (PAGE === "home") renderTodo();
  }
}
// ============================================================ уведомления
function toast(title, text = "", kind = "ok", ms = 5000, onclick = null){
  const box = $("#toasts");
  if (!box || !title) return;
  const el = document.createElement("div");
  el.className = "toast " + (kind === "ok" ? "" : kind);
  el.innerHTML = `<span class="ti">${{ok: "✓", err: "!", warn: "!", info: "i"}[kind] || "✓"}</span><span><b>${esc(title)}</b>${text ? `<span class="sub">${esc(text)}</span>` : ""}</span>`;
  const close = () => { el.classList.add("out"); setTimeout(() => el.remove(), 200) };
  el.onclick = () => { if (onclick) onclick(); close() };
  if (onclick) el.title = "Нажми, чтобы открыть подробности";
  box.appendChild(el);
  while (box.children.length > 4) box.firstChild.remove();
  if (document.hidden) {
    // окно свёрнуто: системное уведомление Windows, а в окне — показать, когда его откроют
    api("/api/notify", {title, text}).catch(() => {});
    const f = () => { if (!document.hidden) { document.removeEventListener("visibilitychange", f); setTimeout(close, ms) } };
    document.addEventListener("visibilitychange", f);
  } else setTimeout(close, ms);
}
const verdictKind = v => ({threat: "err", suspicious: "warn", error: "warn"}[v] || "ok");
const LAUNCH_NAMES = {cleanmgr: "Очистка диска Windows", storagesense: "Контроль памяти", wu: "Windows Update",
  wu_optional: "Необязательные обновления", defender: "Безопасность Windows", startup: "Автозагрузка в Параметрах",
  winget_upgrade: "Обновление программ (winget)", sfc_repair: "Восстановление системных файлов", component_cleanup: "Очистка хранилища компонентов"};
function taskToast(name, t, args = {}){
  if (t.status === "error") return toast("Не получилось", t.error || name, "err", 7000);
  const r = t.result || {};
  const on = !!args.enable;
  const msg = {
    health: () => {
      const C = healthChecks(r), bad = C.filter(c => c.st === "bad").length, warn = C.filter(c => c.st === "warn").length;
      return ["Полная проверка ПК готова", bad ? `нужно исправить: ${bad}, замечаний: ${warn}` : warn ? `замечаний: ${warn}` : "всё в порядке", bad ? "warn" : "ok"];
    },
    sysfiles: () => { const w = (r.cards || []).find(c => c.lvl === "bad") || (r.cards || []).find(c => c.lvl === "warn");
      return w ? [w.title, w.action === "repair" ? "можно восстановить — кнопка в «Полной проверке»" : "подробности — в «Полной проверке»", w.lvl === "bad" ? "warn" : "info"]
               : ["Системные файлы в порядке", "повреждений нет"] },
    drivers: () => ["Сведения о драйверах обновлены", (r.problems || []).length ? `устройств с ошибками: ${r.problems.length}` : "все устройства работают"],
    driver_updates: () => [(r || []).length ? `Найдено обновлений драйверов: ${r.length}` : "Новых драйверов нет", (r || []).length ? "установить можно в Windows Update" : ""],
    cleanup_scan: () => ["Анализ диска готов", ""],
    cleanup_run: () => [`Освобождено ${fmtB(r.freed || 0)}`, r.skipped ? `пропущено занятых файлов: ${r.skipped}` : "временные файлы удалены"],
    autoruns: () => ["Автозагрузка проверена", `записей: ${(r || []).length}, подозрительных: ${(r || []).filter(i => i.level === "bad").length}`],
    network: () => ["Сеть проверена", `соединений: ${(r.connections || []).length}`],
    hosts_set: () => [on ? "Блокировка майнинг-доменов включена" : "Блокировка майнинг-доменов выключена", r.domains ? `доменов в списке: ${r.domains}` : ""],
    watch_set: () => [on ? "Сторож включён" : "Сторож выключен", on ? "проверка раз в 15 минут" : ""],
    noise: () => ["Проверка шума готова", (r.causes || [])[0]?.title || ""],
    hardware: () => ["Комплектующие собраны", ""],
    mem_quick: () => [`Освобождено ${fmtB(r.freed || 0)} памяти`, `занято ${Math.round(r.before?.percent)}% → ${Math.round(r.after?.percent)}%`],
    mem_full: () => [`Освобождено ${fmtB(r.freed || 0)} памяти`, `полная очистка · занято ${Math.round(r.before?.percent)}% → ${Math.round(r.after?.percent)}%`],
    memclean_set: () => r.enabled ? ["Полная очистка памяти включена", "теперь кнопка чистит как Mem Reduct"] : ["Полная очистка памяти выключена", "", "info"],
    sensors_set: () => r.enabled ? ["Датчики включены", "температура процессора и вентиляторы — во вкладке «Ресурсы»"] : ["Датчики выключены", "", "info"],
  }[name];
  if (!msg) return taskToast2(name, t, args);
  const [title, text, kind] = msg();
  toast(title, text, kind || "ok");
}

let UI_VER = null;
let SRV_FAIL = 0;
async function checkVersion(){
  try {
    const {ui} = await api("/api/version");
    if (UI_VER && ui !== UI_VER) location.reload();     // приложение обновили — подтянуть новую версию
    UI_VER = ui;
    if (SRV_FAIL >= 2) location.reload();                 // ScanHub снова запустили — окно оживает само
    SRV_FAIL = 0;
  } catch (e) {
    if (window.__quitting || e?.api) return;
    if (++SRV_FAIL >= 2) srvDead();
  }
}
// сервер ScanHub закрылся, а окно осталось — честно сказать, а не делать вид, что кнопки работают
function srvDead(){
  if (document.getElementById("srvDead")) return;
  document.body.insertAdjacentHTML("beforeend", `<div class="mdl-back" id="srvDead"><div class="mdl"><div class="mdl-top"><span class="mdl-ic">!</span><h3>ScanHub закрылся</h3></div>
    <p>Это окно больше не связано с ScanHub, поэтому кнопки в нём не работают. Открой ScanHub снова — ярлыком на рабочем столе или в меню «Пуск». Если открыть его, пока это окно на экране, оно оживёт само.</p>
    <div class="mdl-btns"><button data-srv-close>Закрыть окно</button></div></div></div>`);
  document.querySelector("[data-srv-close]").onclick = () => window.close();
}
setInterval(checkVersion, 5000); checkVersion();
// пока что-то ставится или обновляется — окно само спрашивает сервер, чтобы кнопки показывали ход, а потом «Запустить»
let BUSY_T = 0;
function watchBusy(){
  if (BUSY_T) return;
  const t0 = Date.now();
  BUSY_T = setInterval(async () => {
    await refresh();
    if (!TOOLS.some(t => t.busy) || Date.now() - t0 > 20 * 60000) { clearInterval(BUSY_T); BUSY_T = 0 }
  }, 1500);
}
async function refresh(){
  try {
    const [r, h] = await Promise.all([api("/api/tools"), api("/api/history")]);
    const wasBusy = new Map(TOOLS.map(t => [t.id, t.busy]));
    TOOLS = r.tools; LAST = r.last_check; HISTORY = h.history;
    for (const t of TOOLS) {
      const b = wasBusy.get(t.id);
      if (!b || t.busy) continue;
      const s = t.state || {};
      if (s.blocked) toast(`${t.name}: заблокирован Defender`, s.blocked, "err", 8000);
      else if (s.error) toast(`${t.name}: не получилось`, s.error, "err", 8000);
      else if (t.ready) toast(/^поиск/.test(b) ? `${t.name}: файл найден` : /обновл/.test(b) ? `${t.name} обновлён` : `${t.name} установлен`,
                              s.installed ? `версия ${s.installed}` : "");
    }
    const typing = document.activeElement && (document.activeElement.id || "").startsWith("tx-");
    if (!typing) render();
    // блоки со сканерами есть и в разделах (глубокая, ультра) — их тоже перерисовываем, если что-то поменялось
    const sig = TOOLS.map(t => t.id + (t.busy || "") + t.ready).join("|");
    if (sig !== refresh.sig) { refresh.sig = sig; if (typeof viewFor === "function" && viewFor() === "panel" && !typing) redrawPanels() }
  } catch(e) { console.error(e) }
}

// ---------- консоль и слежение за задачами
function conOpen(){ $("#console").classList.remove("min") }
$("#conToggle").onclick = () => $("#console").classList.add("min");
$("#conBtn").onclick = () => {
  $("#console").classList.toggle("min");
  if (!openJobs.length) $("#conOut").textContent = "Сейчас ничего не запущено.\n\nЗдесь появляется ход проверок: ультра и глубокой проверки, сканеров, обновления программ — " +
    "какая команда запущена и что она выводит. Прошлые проверки — в «Истории» (кнопка «лог»).";
};
function renderTabs(){
  $("#conTabs").innerHTML = openJobs.map(j => `<span class="tab ${active===j.id?"on":""}" data-tab="${j.id}">
     <span class="dot ${j.status==="running"?"run":(j.verdict?.[0]||"")}"></span>${esc(j.tool_name)} · ${esc(j.mode_label)}
     <span class="x" data-close="${j.id}">✕</span></span>`).join("");
  const a = openJobs.find(j => j.id === active);
  $("#conStop").hidden = !(a && a.status === "running");
}
function show(id){
  active = id;
  const j = openJobs.find(x => x.id === id);
  $("#conOut").textContent = j ? j.text : "";
  renderTabs();
}
async function follow(id, quiet, silent){
  if (openJobs.some(x => x.id === id)) return;           // уже показывается в консоли
  const j = {id, text:"", total:0, status:"running", tool_name:"…", mode_label:""};
  openJobs.push(j);
  if (!quiet) { show(id); if (MODE === "dev") conOpen() }
  else if (!active || !openJobs.some(x => x.id === active)) show(id);     // консоль не пустая: сразу видно, что идёт
  let fails = 0;
  while (true) {
    let r;
    try { r = await api(`/api/job?id=${id}&since=${j.total}`); fails = 0 }
    catch (e) {
      // раньше одна неудачная попытка обрывала слежение — окно навсегда показывало «проверяет…» с тикающим таймером
      const gone = /нет задачи/.test(e.message);           // сервер перезапускался: задачи в памяти нет, итог — в истории
      if (!gone && ++fails < 90) { await new Promise(res => setTimeout(res, 800 + Math.min(fails, 10) * 300)); continue }
      const h = gone && (await api("/api/history").catch(() => null))?.history?.find(x => x.id === id);
      Object.assign(j, h ? {status: "done", verdict: h.verdict, code: h.code, tool: h.tool, tool_name: h.tool_name, mode_label: h.mode_label,
                            target: h.target, batch: h.batch, started: h.started, finished: h.finished}
                         : {status: "lost", verdict: ["error", "окно потеряло связь с проверкой — итог смотри в «Истории»"]});
      renderTabs();
      if (j.batch) { renderSummary(j.batch); if (j.batch === simpleBatch) renderSimpleResult() }
      break;
    }
    Object.assign(j, {tool_name:r.tool_name, mode_label:r.mode_label, status:r.status, verdict:r.verdict, code:r.code, target:r.target, batch:r.batch,
                      tool:r.tool, found:r.found, problems:r.problems, started:r.started, progress:r.progress, details:r.details, finished:r.finished});
    if (!j.text) j.text = `$ ${r.cmd.join(" ")}\n\n`;
    if (r.lines.length) { j.text += r.lines.join("\n") + "\n"; j.total = r.total }
    if (r.status !== "running") j.text += `\n── ${r.verdict?.[1] || "готово"} (код ${r.code}) ──\n`;
    if (active === id) {
      const pre = $("#conOut"), stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
      pre.textContent = j.text; if (stick) pre.scrollTop = pre.scrollHeight;
    }
    renderTabs();
    if (j.batch) { renderSummary(j.batch); if (j.batch === simpleBatch) renderSimpleResult() }
    if (r.status !== "running") {
      if (j.batch) {
        refresh();
        const b = batches[j.batch];
        if (b && !b.notified) {
          const rows = b.jobs.map(x => openJobs.find(o => o.id === x)).filter(Boolean);
          if (rows.length === b.jobs.length && rows.every(o => o.status !== "running")) {
            b.notified = true;
            const w = verdictOf(rows);
            const what = b.quick ? (rows[0]?.mode_label || "Проверка") : b.label || (b.target ? b.target.split("\\").pop() : "Проверка");
            const adv = !b.quick && typeof adviceOf === "function" ? adviceOf(rows, b) : null;     // общий итог «можно запускать?»
            if (adv) toast(adv.title, `${what} · сканеров: ${rows.length}`, {"i-bad": "err", "i-warn": "warn"}[adv.cls] || "ok", adv.cls === "i-bad" ? 12000 : 6000);
            else toast(w === "threat" ? "Найдены угрозы!" : w === "suspicious" ? "Есть подозрения" : w === "error" ? "Не все проверки прошли" : "Проверка завершена: угроз нет",
                  `${what} · сканеров: ${rows.length}`, verdictKind(w), w === "threat" ? 12000 : 6000);
          }
        }
      } else if (!String(id).startsWith("log-") && !silent) {
        toast(`${r.tool_name}: ${r.verdict?.[1] || "готово"}`, r.mode_label, verdictKind(r.verdict?.[0]));
      }
      break;
    }
    await new Promise(res => setTimeout(res, 800));
  }
}
$("#conTabs").onclick = e => {
  const c = e.target.closest("[data-close]");
  if (c) { openJobs = openJobs.filter(j => j.id !== c.dataset.close); show(openJobs.at(-1)?.id); return }
  const t = e.target.closest("[data-tab]"); if (t) show(t.dataset.tab);
};
$("#conStop").onclick = () => active && api("/api/stop", {id:active});

function renderSummary(batch){
  const b = batches[batch]; if (!b || MODE !== "dev" || b.quick) return;
  const rows = b.jobs.map(id => openJobs.find(j => j.id === id)).filter(Boolean);
  const running = rows.some(r => r.status === "running"), w = verdictOf(rows);
  const head = running ? "Проверка идёт…" : w === "threat" ? "Найдены угрозы" : w === "suspicious" ? "Есть подозрения" : w === "error" ? "Не все проверки прошли" : "Угроз не найдено";
  $("#summary").innerHTML = `<div class="summary">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><b>${head}</b>
      <span class="sub" style="font-family:var(--mono);font-size:12px">${esc(b.target)}</span><div style="flex:1"></div><a id="sumClose">закрыть</a></div>
    <table class="t"><tr><th>Инструмент</th><th>Результат</th><th>Код</th><th></th></tr>
    ${rows.map(r => `<tr><td>${esc(r.tool_name)}</td>
      <td><span class="dot ${r.status==="running"?"run":(r.verdict?.[0]||"")}"></span> ${r.status==="running"?"идёт…":esc(r.verdict?.[1])}</td>
      <td>${r.code ?? ""}</td><td><a data-show="${r.id}">вывод</a></td></tr>`).join("")}</table></div>`;
}
$("#summary").onclick = e => {
  if (e.target.id === "sumClose") $("#summary").innerHTML = "";
  const s = e.target.closest("[data-show]"); if (s) { show(s.dataset.show); conOpen() }
};

async function run(toolId, mode, target, batch, quiet){
  try { const r = await api("/api/run", {tool: toolId, mode, target, batch}); follow(r.id, quiet); return r.id }
  catch(e) { say(e.message) }
}
async function scanBatch(target, tools, meta = {}){
  const batch = Math.random().toString(36).slice(2, 10);
  batches[batch] = {target, jobs: [], excluded: excludedOf(tools), ...meta};
  for (const t of tools) {
    const id = await run(t.id, t.modes.find(m => m.multi).id, target, batch, MODE === "simple");
    if (id) batches[batch].jobs.push(id);
  }
  renderSummary(batch);
  return batch;
}

// ---------- клики
document.addEventListener("click", async e => {
  if (e.target.id === "sResClose") { simpleBatch = null; renderSimpleResult(); return }
  if (e.target.id === "openSettings2" || e.target.closest("[data-settings]")) return openSettings();
  const up = e.target.closest("[data-upload]");
  if (up) {
    const svc = up.dataset.upload, file = up.dataset.file, b = batches[simpleBatch];
    if (!await ask(svc === "virustotal"
        ? "Загрузить файл в VirusTotal? Загруженные файлы становятся доступны исследователям безопасности — не загружай личные документы и код, который не должен утечь. Для своих программ это обычное дело."
        : "Загрузить файл в песочницу Filescan? Файл загружается в приватном режиме: его увидишь только ты.")) return;
    const id = await run(svc, "upload", file, simpleBatch, true);
    if (id && b) {                                  // строка «нет в базе» этого сервиса заменяется настоящей проверкой
      b.jobs = b.jobs.filter(j => openJobs.find(x => x.id === j)?.tool !== svc);
      b.jobs.push(id);
    }
    return renderSimpleResult();
  }
  if (e.target.closest("[data-uninstall-self]")) {
    e.preventDefault();
    let info;
    toast("Проверяю, что ScanHub оставил в системе…", "несколько секунд", "info", 8000);
    try { info = await api("/api/uninstall_self", {preview: true}) } catch (err) { return toast("Не получилось", err.message, "err") }
    $("#settings")?.close?.();
    const found = info.traces.filter(t => t.found), admin = found.some(t => t.admin);
    const html = `<p>ScanHub уберёт всё, что он добавил в систему вне своей папки:</p>
      ${found.length ? `<ul class="mdl-list">${found.map(t => `<li>${esc(t.title)}</li>`).join("")}</ul>` : `<p class="sub">Вне своей папки ScanHub ничего не оставил.</p>`}
      <label class="switch" style="margin-top:10px"><input type="checkbox" id="unFolder" checked> <span>Удалить и саму папку ScanHub
        <span class="hint" style="display:block">${esc(info.root)} — программа, история проверок, ключи${info.quarantine ? `, карантин (${info.quarantine} файлов — они удалятся навсегда)` : ""}. Папка удалится через несколько секунд после того, как окно закроется.</span></span></label>
      ${info.undo ? `<div class="note warn" style="margin-top:10px">Изменения настроек Windows, которые ты делал через ScanHub, останутся (их можно отменить: ${info.undo}). Если хочешь вернуть как было — сначала открой «Приватность и защита → Что изменил ScanHub». <a data-go-page="privacy:changes">Открыть</a></div>` : ""}
      ${admin ? `<p class="sub" style="margin-top:8px">Для задач планировщика и файла hosts появится одно окно UAC (в нём будет «Python» — это ScanHub).</p>` : ""}`;
    if (!await modal({title: "Удалить ScanHub с компьютера?", html, ok: "Удалить ScanHub", cancel: "Отмена", danger: true, icon: "!"})) return;
    const folder = !!document.getElementById("unFolder")?.checked;
    let r;
    try { r = await api("/api/uninstall_self", {folder}) } catch (err) { return toast("Не получилось удалить", err.message, "err") }
    if (r.errors?.length && !r.folder && folder) return toast("ScanHub не удалён", r.errors[0], "err", 9000);
    window.__quitting = true;
    document.body.innerHTML = `<div style="min-height:100vh;display:grid;place-items:center;font:15px var(--din, system-ui);color:var(--muted);background:var(--bg)">
      <div style="text-align:center;max-width:520px"><b style="font-size:20px;color:var(--text)">ScanHub удалён</b>
      <p>${r.folder ? "Папка ScanHub удалится через несколько секунд после закрытия этого окна." : "Системные следы убраны. Папку ScanHub можно удалить вручную."}${r.errors?.length ? "<br>" + esc(r.errors.join("; ")) : ""}</p><p>Спасибо, что пользовался!</p></div></div>`;
    setTimeout(() => window.close(), 1500);
    return;
  }
  if (e.target.closest("[data-wipe]")) {
    e.preventDefault();
    if (!await ask("Очистить историю проверок и журналы? Удалятся список прошлых проверок, их журналы и копии перетащенных файлов. Ключи, резервные копии для «вернуть как было» и карантин останутся.", {danger: true})) return;
    const r = await api("/api/wipe", {});
    HISTORY = []; toast("История и журналы очищены", `удалено файлов: ${r.removed}`); return refresh();
  }
  const el = e.target.closest("[data-run],[data-install],[data-update],[data-link],[data-dismiss],[data-view],[data-mode-set],[data-log]");
  if (!el) return;
  if (el.dataset.modeSet) { MODE = el.dataset.modeSet; store.set("mode", MODE); render(); return showPage() }
  if (el.dataset.link) { e.preventDefault(); return api("/api/link", {url: el.dataset.link}) }
  if (el.dataset.log) return openLog(el.dataset.log);
  if (el.dataset.dismiss) { await api("/api/dismiss", {tool: el.dataset.dismiss}); return refresh() }
  if (el.dataset.install || el.dataset.update) {
    const id = el.dataset.install || el.dataset.update;
    el.disabled = true; el.textContent = el.dataset.update ? "Обновляю…" : /Найти|найти/.test(el.textContent) ? "Ищу…" : "Скачиваю…";
    await api("/api/install", {tool: id, update: !!el.dataset.update});
    await refresh();
    return watchBusy();
  }
  if (el.dataset.run) {
    const t = tool(el.dataset.run), m = t.modes.find(x => x.id === el.dataset.mode);
    let target = null;
    if (m.target === "path" || m.target === "file") {
      target = $("#target").value.trim().replace(/^"|"$/g, "");
      if (!target) { $("#target").focus(); return say("Сначала укажи файл или папку в строке сверху") }
    }
    if (m.target === "text" || m.target === "url") { target = $(`#tx-${t.id}-${m.id}`).value.trim(); if (!target) return }
    if (m.upload && !await ask(t.id === "virustotal"
        ? "Файл будет загружен в VirusTotal. Загруженные файлы становятся доступны исследователям безопасности, поэтому не загружай личные документы. Продолжить?"
        : "Файл будет загружен в песочницу Filescan в приватном режиме. Продолжить?")) return;
    if (m.confirm && !await ask(m.confirm, {danger: false})) return;
    const quick = MODE === "simple";
    if (quick && !m.gui && !m.console) { // в простом режиме — показать как результат
      const batch = Math.random().toString(36).slice(2, 10);
      batches[batch] = {target: "", jobs: [], quick: true};
      const id = await run(t.id, m.id, target, batch, true);
      if (id) { batches[batch].jobs.push(id); simpleBatch = batch; go("scan", "check"); renderSimpleResult() }
      return;
    }
    run(t.id, m.id, target);
  }
});
document.addEventListener("change", async e => {
  if (e.target.dataset.auto) {
    await api("/api/auto", {tool: e.target.dataset.auto, value: e.target.checked});
    toast(e.target.checked ? "Автообновление включено" : "Автообновление выключено", tool(e.target.dataset.auto)?.name || "", "info");
    refresh();
  }
  if (e.target.dataset.multi) {
    e.target.checked ? multiSel.add(e.target.dataset.multi) : multiSel.delete(e.target.dataset.multi);
    store.set("multi", JSON.stringify([...multiSel]));
  }
});
$("#pickFile").onclick = async () => { const r = await api("/api/pick", {kind:"file"}); if (r.path) $("#target").value = r.path };
$("#pickFolder").onclick = async () => { const r = await api("/api/pick", {kind:"folder"}); if (r.path) $("#target").value = r.path };
$("#target").addEventListener("keydown", e => { if (e.key === "Enter") $("#scanAll").click() });
$("#scanAll").onclick = async () => {
  const target = $("#target").value.trim().replace(/^"|"$/g, "");
  if (!target) { $("#target").focus(); return say("Укажи файл или папку") }
  const tools = TOOLS.filter(t => t.ready && !t.data_missing && multiSel.has(t.id) && t.modes.some(m => m.multi));
  if (!tools.length) return say("Не выбрано ни одного готового инструмента");
  scanBatch(target, tools);
};
$("#checkBtn").onclick = async () => {
  $("#checkBtn").disabled = true; $("#checkBtn").textContent = "Проверяю…";
  await api("/api/check", {});
  setTimeout(async () => { await refresh(); $("#checkBtn").disabled = false; $("#checkBtn").textContent = "Проверить обновления" }, 5000);
};

// ---------- история
async function loadHistory(){
  const {history} = await api("/api/history");
  $("#history").innerHTML = history.length ? `<table class="t">
    <tr><th>Когда</th><th>Инструмент</th><th>Режим</th><th>Цель</th><th>Результат</th><th>Код</th><th></th></tr>
    ${history.map(h => `<tr><td>${esc(h.started.replace("T"," "))}</td><td>${esc(h.tool_name)}</td><td>${esc(h.mode_label)}</td>
      <td class="p" title="${esc(h.target||"")}">${esc(h.target||"—")}</td>
      <td><span class="dot ${h.verdict?.[0]||""}"></span> ${esc(h.verdict?.[1]||"")}</td><td>${h.code ?? ""}</td>
      <td><a data-log="${h.id}">лог</a></td></tr>`).join("")}</table>` : `<div class="empty">Проверок ещё не было</div>`;
}
async function openLog(id){
  const {text} = await api(`/api/log?id=${id}`);
  const j = {id:"log-"+id, text, status:"done", tool_name:"Лог", mode_label:id, verdict:["",""]};
  openJobs = openJobs.filter(x => x.id !== j.id); openJobs.push(j); show(j.id); conOpen();
}

// ---------- настройки
let USAGE;                       // анонимная статистика: true/false — ответил, null — ещё не спрашивали, undefined — не загружено
async function openSettings(){
  CFG = await api("/api/config");
  const f = $("#settingsForm");
  f.reset();
  f.check_every_hours.value = CFG.check_every_hours;
  for (const k of ["vt_files", "fs_files", "smart_mb"]) f[k].value = CFG[k];
  f.folder_full.checked = !!CFG.folder_full;
  f.ctx_menu.checked = !!CFG.ctx_menu;
  try { USAGE = (await api("/api/usage")).on ?? null } catch {}
  f.usage_ping.checked = USAGE === true;
  $("#vtState").textContent = CFG.virustotal_key ? "· сохранён ✓" : "· не задан";
  $("#fsState").textContent = CFG.filescan_key ? "· сохранён ✓" : "· не задан";
  $("#mdState").textContent = CFG.metadefender_key ? "· сохранён ✓" : "· не задан";
  $("#haState").textContent = CFG.hybrid_key ? "· сохранён ✓" : "· не задан";
  $("#ghState").textContent = CFG.github_token ? "· сохранён ✓" : "";
  $("#settings").showModal();
}
$("#settingsBtn").onclick = openSettings;
// «Выйти»: сервер выключается сразу; если идёт проверка — сначала спросить
$("#quitBtn").onclick = async () => {
  const quit = async force => {
    const r = await fetch("/api/quit", {method: "POST", headers: {"X-Token": TOKEN, "Content-Type": "application/json"}, body: JSON.stringify({force})});
    return {code: r.status, j: await r.json().catch(() => ({}))};
  };
  try {
    let {code, j} = await quit(false);
    if (code === 409) {
      const what = [...(j.jobs || []), ...(j.tasks || []).map(t => "задача " + t)];
      if (!await modal({title: "Сейчас идёт работа — остановить и выйти?", danger: true, icon: "!", ok: "Остановить и выйти", cancel: "Не выходить",
                        body: "Если выйти сейчас, эти проверки оборвутся. Можно просто закрыть окно — ScanHub доработает и выключится сам.",
                        list: what.slice(0, 8)})) return;
      ({code} = await quit(true));
    }
    if (code !== 200) throw new Error("сервер не ответил");
  } catch (e) { return toast("Не получилось выйти", e.message, "err") }
  window.__quitting = true;
  document.body.innerHTML = `<div style="min-height:100vh;display:grid;place-items:center;font:15px var(--din, system-ui);color:var(--muted);background:var(--bg)">
    <div style="text-align:center"><b style="font-size:20px;color:var(--text)">ScanHub закрыт</b><p>Окно можно закрыть. Чтобы открыть снова — ярлык на рабочем столе.</p></div></div>`;
  setTimeout(() => window.close(), 300);
};
$("#settings").addEventListener("close", async () => {
  if ($("#settings").returnValue !== "save") return;
  const f = $("#settingsForm"), body = {check_every_hours: +f.check_every_hours.value || 6, vt_files: +f.vt_files.value || 8,
    fs_files: +f.fs_files.value || 20, smart_mb: +f.smart_mb.value || 100, folder_full: f.folder_full.checked};
  for (const k of ["virustotal_key", "filescan_key", "metadefender_key", "hybrid_key", "github_token"]) {
    const v = f[k].value.trim();
    if (v === "-") body[k] = ""; else if (v) body[k] = v;
  }
  await api("/api/config", body);
  if (f.usage_ping.checked !== (USAGE === true)) USAGE = (await api("/api/usage", {on: f.usage_ping.checked}).catch(() => ({on: USAGE}))).on;
  if (f.ctx_menu.checked !== !!CFG.ctx_menu) {
    const r = await api("/api/ctxmenu", {enable: f.ctx_menu.checked}).catch(e => ({error: e.message}));
    toast(r.on ? "Пункт «Проверить в ScanHub» добавлен" : r.error ? "Не получилось изменить меню" : "Пункт «Проверить в ScanHub» убран",
          r.on ? "Правая кнопка по файлу или папке. В Windows 11 — в «Показать дополнительные параметры»" : (r.error || ""), r.error ? "bad" : "ok", 8000);
  }
  toast("Настройки сохранены", Object.keys(body).filter(k => k.endsWith("key") || k.endsWith("token")).length ? "ключи обновлены" : "");
  $("#every").textContent = body.check_every_hours;
  refresh();
});


// ---------- файл из меню «Проверить в ScanHub»: сервер передаёт его окну
async function pendingCheck(){
  try {
    const r = await api("/api/pending");
    if (!r.path) return;
    if (!TOOLS.length) await refresh();
    toast("Проверяю из меню", r.path.split("\\").pop(), "info", 4000);
    await simpleScanPath(r.path, r.kind);
  } catch {}
}
setInterval(pendingCheck, 2000);

// ---------- клавиатура: всё, что нажимается мышью, доступно и с клавиатуры (Tab — перейти, Enter/пробел — нажать)
const KBD_SEL = "a:not([href]), [data-diag-det], [data-det], [data-stab], [data-stab-day], [data-diag-pick], [data-ustep], [data-dall-sort], summary";
function kbdify(root){
  if (root.nodeType !== 1) return;
  const els = root.matches?.(KBD_SEL) ? [root, ...root.querySelectorAll(KBD_SEL)] : root.querySelectorAll(KBD_SEL);
  for (const el of els) {
    if (el.hasAttribute("tabindex") || el.tagName === "SUMMARY") continue;
    el.tabIndex = 0;
    el.setAttribute("role", "button");
  }
}
document.addEventListener("keydown", e => {
  const el = e.target;
  if ((e.key === "Enter" || e.key === " ") && el?.getAttribute?.("role") === "button" && !/^(BUTTON|INPUT|SELECT|TEXTAREA)$/.test(el.tagName)) {
    e.preventDefault();
    el.click();
  }
});
document.addEventListener("DOMContentLoaded", () => {
  kbdify(document.body);
  new MutationObserver(ms => { for (const m of ms) m.addedNodes.forEach(kbdify) }).observe(document.body, {childList: true, subtree: true});
});
