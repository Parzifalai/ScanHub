// ============================================================ ЯЗЫК ИНТЕРФЕЙСА (русский / English)
// Тексты ScanHub пишутся по-русски; в режиме English окно на лету заменяет их по словарю en.json
// (фразы и куски фраз, собранные из кода — dev\i18n_extract.py). Работает для всего, что появляется в окне:
// разделы, кнопки, подсказки, сообщения сервера, окна подтверждения. Ответы ИИ-помощника — сразу по-английски.
const LANG = (() => { try { return localStorage.getItem("lang") === "en" ? "en" : "ru" } catch { return "ru" } })();
document.documentElement.lang = LANG;
let I18N = null, I18N_RX = null;
const CYR = /[А-Яа-яЁё]/;
const I18N_ATTRS = ["title", "placeholder", "aria-label"];

const LOC = LANG === "en" ? "en-GB" : "ru";                    // даты и числа в toLocale…
// единицы и связки, которые приходят вперемешку с числами: «19,6 ГБ из 199 ГБ», «5 мин назад», «за 30 дн.»
const I18N_UNITS = [
  [/(\d),(\d+)(?=\s?(?:[ГМКТ]Б|с|мс|Вт|%)(?![А-Яа-яЁё]))/g, "$1.$2"],
  [/(\d)\s?ГБ(?![А-Яа-яЁё])/gi, "$1 GB"], [/(\d)\s?МБ(?![А-Яа-яЁё])/gi, "$1 MB"], [/(\d)\s?КБ(?![А-Яа-яЁё])/gi, "$1 KB"],
  [/(\d)\s?ТБ(?![А-Яа-яЁё])/g, "$1 TB"], [/(\d)\s?Б(?![А-Яа-яЁё])/g, "$1 B"], [/(\d)\s?Вт(?![А-Яа-яЁё])/g, "$1 W"],
  [/(\d)\s?Гц(?![А-Яа-яЁё])/g, "$1 Hz"], [/(\d)\s?МГц(?![А-Яа-яЁё])/g, "$1 MHz"], [/(\d)\s?ГГц(?![А-Яа-яЁё])/g, "$1 GHz"],
  [/(\d)\s?мс(?![А-Яа-яЁё])/g, "$1 ms"], [/(\d)\s?мин\.?(?![А-Яа-яЁё])/g, "$1 min"], [/(\d)\s?ч(?![А-Яа-яЁё])/g, "$1 h"],
  [/(\d)\s?с(?![А-Яа-яЁё])/g, "$1 s"], [/(\d)\s?(?:дн\.?|дней|дня|день)(?![А-Яа-яЁё])/g, "$1 days"],
  [/(\d)\s?мес\.?(?![А-Яа-яЁё])/g, "$1 mo."], [/(\d)\s?(?:лет|года?)(?![А-Яа-яЁё])/g, "$1 years"],
  [/(\d)\s?шт\.?(?![А-Яа-яЁё])/g, "$1 pcs."], [/(\d)\s?Мбит\/с/g, "$1 Mbit/s"], [/(\d)\s?об\/мин/g, "$1 RPM"],
  [/(\d)из(?=\s)/g, "$1 of"], [/(^|[\s(])из(?=\s+[\d~]|\s*$)/g, "$1of"], [/(^|[\s(])С\s+(?=\d)/g, "$1Since "], [/(min|h|s|days|mo\.|years)\s+назад/g, "$1 ago"],
  [/(^|[\s(·])за\s+(?=\d)/g, "$1over "], [/(^|[\s(])код\s+(?=0x|\d)/g, "$1code "], [/(^|\s)от\s+(?=\d{4}-)/g, "$1from "],
];
const I18N_EN = [[/(?<![\d.,])1 (day|hour|minute|file|folder|program|threat|item|step|time|driver|app)s\b/g, "1 $1"],
                 [/(?<![\d.,])1 entries\b/g, "1 entry"]];
function tr(s){
  if (!I18N || !s || !CYR.test(s)) return s;
  const t = s.trim();
  if (I18N[t] != null) return s.replace(t, I18N[t]);
  let r = s.replace(I18N_RX, m => I18N[m] ?? m);
  if (CYR.test(r)) for (const [rx, to] of I18N_UNITS) r = r.replace(rx, to);
  for (const [rx, to] of I18N_EN) r = r.replace(rx, to);
  return r;
}
function trNode(node){
  if (!I18N) return;
  if (node.nodeType === 3) {                                   // текст
    const p = node.parentNode;
    if (p && (p.nodeName === "SCRIPT" || p.nodeName === "STYLE" || p.closest?.("[data-noi18n],.mono,pre,code,textarea,input"))) return;
    const v = node.nodeValue, n = tr(v);
    if (n !== v) node.nodeValue = n;
    return;
  }
  if (node.nodeType !== 1) return;
  for (const a of I18N_ATTRS) {
    const v = node.getAttribute?.(a);
    if (v && CYR.test(v)) { const n = tr(v); if (n !== v) node.setAttribute(a, n) }
  }
  if (node.matches?.("[data-noi18n],pre,code,textarea,.mono")) return;
  for (const c of node.childNodes) trNode(c);
}
async function i18nStart(){
  if (LANG !== "en") return;
  try {
    I18N = await (await fetch("/en.json", {headers: {"X-Token": TOKEN}})).json();
  } catch { return }
  const keys = Object.keys(I18N).filter(k => I18N[k] && k.trim().length > 2).sort((a, b) => b.length - a.length);
  const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // фразы из нескольких слов заменяются в любом месте; одиночное слово — только если рядом нет других русских слов,
  // иначе выходит каша вроде «Assistant по входу в учетную entry» (названия служб и программ Windows остаются как есть)
  const free = k => /\s|:$/.test(k.trim());                     // фраза или подпись «Почему:» — заменяется где угодно
  const multi = keys.filter(free), single = keys.filter(k => !free(k));
  I18N_RX = new RegExp(`(?<![А-Яа-яЁё])(?:${multi.map(esc).join("|")})(?![А-Яа-яЁё])` +
    `|(?<![А-Яа-яЁё][\\s«»"]*)(?:${single.map(esc).join("|")})(?![\\s«»"]*[А-Яа-яЁё])`, "g");
  trNode(document.body);
  document.title = tr(document.title);
  new MutationObserver(muts => {
    for (const m of muts) {
      if (m.type === "characterData") trNode(m.target);
      else if (m.type === "attributes") trNode(m.target);
      else m.addedNodes.forEach(trNode);
    }
  }).observe(document.body, {subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: I18N_ATTRS});
}
function setLang(l){
  try { localStorage.setItem("lang", l) } catch {}
  api("/api/config", {lang: l}).catch(() => {}).finally(() => location.reload());
}
document.addEventListener("click", e => {
  const a = e.target.closest("[data-lang]");
  if (a) { e.preventDefault(); setLang(a.dataset.lang) }
});
document.addEventListener("DOMContentLoaded", i18nStart);       // переключатель языка — в начале ⚙ Настроек (index.html)
document.addEventListener("DOMContentLoaded", () => document.querySelectorAll(".set-lang [data-lang]").forEach(b => b.classList.toggle("on", b.dataset.lang === LANG)));
