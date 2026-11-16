// ============================================================ ДВИЖЕНИЕ 2.2: стекло, сворачиваемое меню, агент по Ctrl+K
// Всё здесь — поверх готовых модулей: ничего не ломается, если файл не загрузился.
// Правила: анимируются только transform / opacity / filter; всё короче секунды; «уменьшить движение» в Windows — без анимаций.
const RM = matchMedia("(prefers-reduced-motion: reduce)");
const calm = () => RM.matches;

// ---------- заставка: первый запуск окна за сеанс — логотип рисуется; перезагрузки окна — короткое проявление
(() => {
  const first = (() => { try { return !sessionStorage.getItem("scanhub.booted") } catch { return true } })();
  try { sessionStorage.setItem("scanhub.booted", "1") } catch {}
  document.body.classList.add(first && !calm() ? "boot-full" : "boot-quick");
  // CSS сам прячет заставку по таймеру; здесь только убираем её из документа
  setTimeout(() => document.getElementById("boot")?.remove(), first ? 1700 : 700);
})();

// ---------- меню: свернуть в полоску иконок (запоминается)
function sideMini(on, save = true){
  document.body.classList.toggle("side-mini", on);
  if (save) store.set("sideMini", on ? "1" : "");
  NAV_Y = null;                                      // у свёрнутого меню другие отступы — подсветку ставим сразу, без поездки
  if (typeof renderNav === "function") renderNav();
}
if (store.get("sideMini") === "1") document.body.classList.add("side-mini");
document.addEventListener("click", e => {
  if (!e.target.closest("[data-side-fold]")) return;
  e.preventDefault();
  sideMini(!document.body.classList.contains("side-mini"));
});

// ---------- подсветка текущего раздела переезжает к новому пункту (меню перерисовывается целиком — помним, где она была)
let NAV_Y = null;
const _renderNav = renderNav;
renderNav = function(){
  _renderNav.apply(this, arguments);
  const box = document.querySelector("#side .nav-main"), on = box?.querySelector("a.nav.on");
  if (!box) return;
  const ind = document.createElement("i");
  ind.className = "nav-ind"; ind.setAttribute("aria-hidden", "true");
  if (!on) { ind.style.opacity = 0; box.prepend(ind); NAV_Y = null; return }
  // место считаем ДО вставки и ставим без анимации: иначе новая подсветка рождается вверху и едет вниз
  // при каждой перерисовке меню (а оно перерисовывается каждые несколько секунд вместе со счётчиками)
  const y = on.offsetTop, h = on.offsetHeight;
  const move = NAV_Y != null && NAV_Y !== y && !calm();
  ind.style.height = h + "px";
  ind.style.transition = "none";
  ind.style.transform = `translateY(${move ? NAV_Y : y}px)`;
  box.prepend(ind);
  ind.getBoundingClientRect();
  ind.style.transition = "";
  if (move) ind.style.transform = `translateY(${y}px)`;   // раздел сменился — плавно к новому пункту
  NAV_Y = y;
};

// ---------- смена раздела: блоки появляются по очереди (только в первые ~0,9 с после перехода)
let ENTER_T = 0;
const _showPage = showPage;
showPage = function(){
  const prev = document.body.dataset.page;
  _showPage.apply(this, arguments);
  enterView(prev !== document.body.dataset.page, 0);
};
// delay — пауза перед первым блоком (на запуске ждём, пока уйдёт заставка)
function enterView(restagger, delay){
  if (calm()) return;
  const v = document.querySelector("main .view:not([hidden])");
  if (!v) return;
  const head = document.getElementById("pageHead");
  if (restagger) stagger(v);
  for (const el of [v, head]) { el.style.setProperty("--d0", delay + "ms"); el.classList.remove("enter"); el.getBoundingClientRect(); el.classList.add("enter") }
  clearTimeout(ENTER_T);
  ENTER_T = setTimeout(() => document.querySelectorAll(".enter").forEach(el => el.classList.remove("enter")), 950 + delay);
}
// номер по порядку для задержки: прямые блоки раздела, кнопки быстрых действий, карточки «Проверки»
function stagger(v){
  let i = 0;
  const set = el => el.style.setProperty("--i", i++);
  for (const el of v.children) {
    set(el);
    el.querySelectorAll(":scope > .quick > .qa, :scope > .actions > .action, :scope .home-top > *").forEach(set);
  }
}

// ---------- цифры: при первом появлении отсчитываются от нуля, при обновлении — плавно перетекают
const NUMS = new Map();
function tweenIn(root){
  if (!root) return;
  root.querySelectorAll("b.v, .kpi .v").forEach((b, idx) => {
    const tn = [...b.childNodes].find(n => n.nodeType === 3 && /\d/.test(n.nodeValue));
    if (!tn) return;
    const m = tn.nodeValue.match(/^(\s*)(\d+(?:[.,]\d+)?)(.*)$/s);
    if (!m) return;
    const key = (root.id || "") + ":" + (b.closest(".hs,.kpi")?.querySelector(".k,h4,.l")?.textContent || idx);
    const dec = m[2].includes(",") ? "," : m[2].includes(".") ? "." : "";
    const places = dec ? m[2].split(dec)[1].length : 0;
    const to = parseFloat(m[2].replace(",", "."));
    const from = NUMS.has(key) ? NUMS.get(key) : 0;
    NUMS.set(key, to);
    if (calm() || from === to) return;
    const dur = NUMS.size && from ? 520 : 900, t0 = performance.now();
    const fmt = x => { let s = x.toFixed(places); return dec === "," ? s.replace(".", ",") : s };
    const step = now => {
      if (!tn.isConnected) return;
      const k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(2, -10 * k);      // быстро в начале, мягко в конце
      tn.nodeValue = m[1] + fmt(from + (to - from) * (k === 1 ? 1 : e)) + m[3];
      if (k < 1) requestAnimationFrame(step);
    };
    tn.nodeValue = m[1] + fmt(from) + m[3];
    requestAnimationFrame(step);
  });
}
for (const id of ["hStats", "resKpis"]) {
  const el = document.getElementById(id);
  if (el) new MutationObserver(() => tweenIn(el)).observe(el, {childList: true});   // только перерисовки, не свои же правки текста
}

// ---------- агент: Ctrl+K открывает и ставит курсор в поле; закрытие — с короткой анимацией
document.addEventListener("keydown", e => {
  if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey || e.code !== "KeyK") return;
  e.preventDefault();
  if (document.querySelector(".mdl-back, dialog[open]")) return;
  if (typeof aiPanel !== "function") return;
  aiOpenFull();
});
// ---------- агент открылся/закрылся: страница перестраивается под новую ширину за один раз, а блоки плавно
// доезжают со старых мест на новые (запомнили, где были → перестроили → каждый блок едет от старого места к новому).
// Промежуточных раскладок нет — значит, нечему и перескакивать из двух колонок в одну на полпути.
function flipMain(change){
  if (calm() || innerWidth < 1180 || document.body.classList.contains("ai-full")) return change();
  const sel = ["> *", ".home-top > *", ".quick > .qa", ".quick-more > .qa", ".actions > .action", ".sec-row", ".tiles > *", "#panelBox .pnl", ".hero-text", ".shield-wrap"]
    .map(s => `main .view:not([hidden]) ${s}`).join(",") + ",#pageHead .page-h > *,#pageHead .tabs";
  const all = [...document.querySelectorAll(sel)];
  const els = all.filter(e => !all.some(o => o !== e && e.contains(o)));        // только «листья»: родитель и ребёнок не едут дважды
  const vis = r => r.bottom > -40 && r.top < innerHeight + 40;
  const before = new Map(els.map(e => [e, e.getBoundingClientRect()]));
  change();
  for (const [e, a] of before) {
    const b = e.getBoundingClientRect();
    if (!vis(a) && !vis(b)) continue;
    const dx = a.left - b.left, dy = a.top - b.top;
    if (Math.abs(dx) < 1 && Math.abs(dy) < 1) continue;
    e.animate([{transform: `translate(${dx}px,${dy}px)`}, {transform: "none"}], {duration: 460, easing: "cubic-bezier(.2,.8,.2,1)"});
  }
}
// 2.2: из меню и по Ctrl+K агент открывается разделом на всё окно; «✦ Как решить» и другие кнопки на страницах —
// панелью сбоку, чтобы находка оставалась перед глазами
let AI_FULL_REQ = false;
if (typeof aiOpen === "function") {
  const _aiOpen = aiOpen;
  aiOpen = function(){
    const full = AI_FULL_REQ; AI_FULL_REQ = false;
    if (!full && aiPanel().hidden) document.body.classList.remove("ai-full");
    let r; const args = arguments;
    flipMain(() => { r = _aiOpen.apply(this, args) });
    return r;
  };
}
function aiOpenFull(){
  const p = aiPanel();
  if (!p.hidden && document.body.classList.contains("ai-full")) return document.getElementById("aiText")?.focus();
  if (!p.hidden) return aiFull(true);                   // была панель сбоку — разворачиваем
  AI_FULL_REQ = true;
  document.body.classList.add("ai-full");
  aiOpen();
}
// переход в любой раздел меню закрывает агента на всё окно — как переход между разделами
document.addEventListener("click", e => {
  if (!document.body.classList.contains("ai-full") || !document.body.classList.contains("ai-open")) return;
  if (e.target.closest("#side a.nav, #side .brand, [data-go], [data-go-page]") && !e.target.closest("#aiPanel")) aiClose();
}, true);
// скрыть левое меню целиком (только когда агент на всё окно) — кнопка слева в шапке агента, запоминается
function sideHidden(on){
  document.body.classList.toggle("side-hidden", on);
  store.set("sideHidden", on ? "1" : "");
  const b = document.getElementById("aiSideTgl");
  if (b) b.title = b.ariaLabel = on ? "Показать меню" : "Скрыть меню";
}
if (store.get("sideHidden") === "1") document.body.classList.add("side-hidden");
document.addEventListener("click", e => {
  if (!e.target.closest("#aiSideTgl")) return;
  e.preventDefault(); e.stopPropagation();
  sideHidden(!document.body.classList.contains("side-hidden"));
}, true);
if (typeof aiClose === "function") {
  const _aiClose = aiClose;
  aiClose = function(){
    const p = aiPanel();
    if (p.hidden || calm()) return _aiClose.apply(this, arguments);
    p.classList.add("closing");
    flipMain(() => document.body.classList.remove("ai-open"));     // страница расширяется одновременно с уходом панели
    setTimeout(() => { p.classList.remove("closing"); _aiClose() }, 190);
  };
}
// ---------- агент на весь экран: только разговор, остальное окно прячется (кнопка ⤢ в шапке агента, запоминается)
function aiFull(on){
  document.body.classList.toggle("ai-full", on);
  const b = document.getElementById("aiFull");
  if (b) { b.title = b.ariaLabel = on ? "Панелью сбоку" : "На всё окно"; b.classList.toggle("on", on) }
  if (!aiPanel().hidden) aiRender();                    // пустой экран на всё окно и сбоку выглядит по-разному
}
new MutationObserver(() => { const b = document.getElementById("aiFull"), on = document.body.classList.contains("ai-full");
  if (b && b.classList.contains("on") !== on) { b.classList.toggle("on", on); b.title = b.ariaLabel = on ? "Панелью сбоку" : "На всё окно" } })
  .observe(document.body, {attributes: true, attributeFilter: ["class"]});
document.addEventListener("click", e => {
  if (!e.target.closest("#aiFull")) return;
  e.preventDefault(); e.stopPropagation();
  aiFull(!document.body.classList.contains("ai-full"));
}, true);
// ---------- запуск: раздел уже открыт до этого файла — перерисовать меню (свёрнутость, подсветка) и показать блоки по очереди
renderNav();
enterView(true, document.body.classList.contains("boot-full") ? 820 : 120);
tweenIn(document.getElementById("hStats"));

// подсветка строки агента в меню, пока панель открыта
new MutationObserver(() => document.getElementById("aiTop")?.classList.toggle("on", document.body.classList.contains("ai-open")))
  .observe(document.body, {attributes: true, attributeFilter: ["class"]});
