// ============================================================ 2.4: живые сценки, пока агент работает
// Над списком «что сейчас делаю» — маленькая сцена по смыслу текущего шага (радар для майнеров, луч по файлам для антивируса,
// волны для сети…), время работы и число шагов.
// Перерисовка окна каждую секунду не перезапускает анимацию: у всех циклов период делит 60 с, а сдвиг фазы (--ph) считается
// от общих часов — новая разметка продолжает движение с того же места.
const SCENE_RULES = [
  ["hw", /датчик|комплектующ|железо|шум|нагрев|питани|батаре|устройств|телефон|здоровье|hardware/i],
  ["radar", /майнер|miner|процесс|нагру|автозагруз|startup|слушаю нагрузку/i],
  ["scan", /defender|вирус|защит|карантин|угроз|hijack|hjt|файл|провер\w* (файл|папк)|результат проверки|сканер|драйвер\w* уязв/i],
  ["net", /сеть|сети|интернет\b(?! —)|wi-?fi|проверяю интернет|dns|соединени/i],
  ["log", /журнал|сбо|событ|служб|планировщик|истори|обновлени|прошивк|драйвер/i],
  ["web", /ищу в интернете|страниц|официальн|сайт|web/i],
  ["disk", /мест|диск|мусор|очист|папк|ищу файлы|программ/i],
  ["mem", /запомина|вспомина|забываю|прошлые разговоры/i],
];
const SCENE_NAME = {radar: "ищу скрытое", scan: "проверяю", net: "слушаю сеть", hw: "смотрю железо", log: "читаю журналы",
  web: "ищу в интернете", disk: "смотрю диск", mem: "память", think: "думаю"};
function sceneKind(step){
  const s = String(step || "");
  if (/^ищу в интернете|^читаю страницу|^ищу официальный/i.test(s)) return "web";
  for (const [k, re] of SCENE_RULES) if (re.test(s)) return k;
  return "think";
}
const SCENE_SVG = {
  // радар: вращающийся луч и вспыхивающие точки
  radar: `<circle cx="60" cy="36" r="30" class="sc-ring"/><circle cx="60" cy="36" r="19" class="sc-ring"/><circle cx="60" cy="36" r="8" class="sc-ring"/>
    <path d="M60 6v60M30 36h60" class="sc-grid"/><g class="sc-sweep"><path d="M60 36 L60 6 A30 30 0 0 1 86 21 Z" class="sc-beam"/><path d="M60 36V6" class="sc-beam-edge"/></g>
    <circle cx="76" cy="24" r="2.4" class="sc-blip b1"/><circle cx="44" cy="47" r="2" class="sc-blip b2"/><circle cx="71" cy="52" r="1.8" class="sc-blip b3"/>`,
  // антивирус: стопка файлов, по ним идёт сканирующий луч
  scan: `<g class="sc-files"><rect x="38" y="12" width="30" height="40" rx="4" class="sc-file f3"/><rect x="45" y="16" width="30" height="40" rx="4" class="sc-file f2"/>
    <rect x="52" y="20" width="30" height="40" rx="4" class="sc-file"/><path d="M58 31h18M58 37h14M58 43h18M58 49h10" class="sc-lines"/></g>
    <g class="sc-beamv"><rect x="34" y="0" width="58" height="3" rx="1.5" class="sc-laser"/><rect x="34" y="-14" width="58" height="14" class="sc-glow"/></g>
    <path d="M88 50l4 4 8-9" class="sc-check"/>`,
  // сеть: антенна и расходящиеся волны
  net: `<path d="M60 58V40" class="sc-mast"/><circle cx="60" cy="38" r="3.2" class="sc-node"/>
    <path d="M48 26a17 17 0 0 0 0 24M72 26a17 17 0 0 1 0 24" class="sc-wave w1"/><path d="M40 18a29 29 0 0 0 0 40M80 18a29 29 0 0 1 0 40" class="sc-wave w2"/>
    <path d="M32 10a41 41 0 0 0 0 56M88 10a41 41 0 0 1 0 56" class="sc-wave w3"/><circle cx="60" cy="38" r="3.2" class="sc-ping"/>`,
  // железо: вентилятор и столбик термометра
  hw: `<g class="sc-fanbox"><circle cx="48" cy="36" r="22" class="sc-ring"/><g class="sc-fan"><path d="M48 36c0-10 5-16 10-16-1 8-4 12-10 16zM48 36c10 0 16 5 16 10-8-1-12-4-16-10zM48 36c0 10-5 16-10 16 1-8 4-12 10-16zM48 36c-10 0-16-5-16-10 8 1 12 4 16 10z" class="sc-blade"/></g><circle cx="48" cy="36" r="3" class="sc-node"/></g>
    <rect x="84" y="12" width="9" height="40" rx="4.5" class="sc-tube"/><circle cx="88.5" cy="56" r="7" class="sc-bulb"/><rect x="86.5" y="22" width="4" height="34" rx="2" class="sc-merc"/>`,
  // журналы: строки бегут вверх, одна подсвечена
  log: `<defs><clipPath id="scLogClip"><rect x="33" y="11" width="54" height="50" rx="3"/></clipPath></defs><rect x="30" y="8" width="60" height="56" rx="6" class="sc-sheet"/><g clip-path="url(#scLogClip)"><g class="sc-roll">
    ${[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map(i => `<rect x="38" y="${14 + i * 8}" width="${[40, 30, 44, 24, 36, 42][i % 6]}" height="3" rx="1.5" class="sc-row${i % 5 === 3 ? " hot" : ""}"/>`).join("")}</g></g>
    <rect x="30" y="31" width="60" height="9" class="sc-lens"/>`,
  // интернет: глобус с бегущими меридианами и спутником
  web: `<circle cx="60" cy="36" r="24" class="sc-globe"/><g class="sc-merid"><ellipse cx="60" cy="36" rx="9" ry="24" class="sc-grid"/><ellipse cx="60" cy="36" rx="18" ry="24" class="sc-grid"/></g>
    <path d="M36 36h48M40 24h40M40 48h40" class="sc-grid"/><g class="sc-orbit"><circle cx="60" cy="4" r="3" class="sc-sat"/></g>`,
  // диск: пластина крутится, сектора заполняются
  disk: `<circle cx="60" cy="36" r="27" class="sc-plate"/><g class="sc-spin"><path d="M60 36 L60 9 A27 27 0 0 1 83 22 Z" class="sc-sector"/><path d="M60 36 L83 50 A27 27 0 0 1 60 63 Z" class="sc-sector s2"/></g>
    <circle cx="60" cy="36" r="17" class="sc-ring"/><circle cx="60" cy="36" r="4" class="sc-node"/><path d="M92 14 L72 30" class="sc-arm"/><circle cx="92" cy="14" r="3" class="sc-node"/>`,
  // память: шар, к которому слетаются искры
  mem: `<circle cx="60" cy="36" r="14" class="sc-orbcore"/>${[0, 1, 2, 3, 4, 5].map(i => `<circle cx="60" cy="36" r="2" class="sc-spark k${i}"/>`).join("")}<circle cx="60" cy="36" r="20" class="sc-halo"/>`,
  // думает: шар и орбиты
  think: `<circle cx="60" cy="36" r="13" class="sc-orbcore"/><ellipse cx="60" cy="36" rx="30" ry="11" class="sc-ring o1"/><ellipse cx="60" cy="36" rx="30" ry="11" class="sc-ring o2"/>
    <g class="sc-orbit o1"><circle cx="90" cy="36" r="2.6" class="sc-sat"/></g><g class="sc-orbit o2"><circle cx="30" cy="36" r="2.2" class="sc-sat"/></g>`,
};
const SCENE_LAST = {};               // какая сцена была у этого ответа (чат и карточка вывода — отдельно)
// 2.5: «лента шагов» — сценка, время и «Остановить» сверху, под ними полоска хода и шаги: пройденные с галочкой, текущий светится.
// Одинаковые шаги подряд склеиваются в один с «×2». Видно не больше 6 последних, остальные — строкой «раньше ещё N».
const RUN_LAST = {};
function aiRunGroup(st){
  return st.reduce((a, s) => (a.length && a[a.length - 1].s === s ? a[a.length - 1].n++ : a.push({s, n: 1}), a), []);
}
function aiRun(steps, t0, stop = "", first = "думаю…"){
  const st = (steps || []).filter(Boolean), g = aiRunGroup(st.length ? st : [first]);
  const cur = g[g.length - 1], k = sceneKind(st.length ? cur.s : "");
  const fresh = SCENE_LAST[t0] !== k; SCENE_LAST[t0] = k;
  const step = RUN_LAST[t0] !== g.length; RUN_LAST[t0] = g.length;
  const ph = -((Date.now() / 1000) % 60), shown = g.slice(-6), hid = g.length - shown.length;
  const x = n => n > 1 ? ` <span class="agr-x">×${n}</span>` : "";
  return `<div class="agr">
    <div class="agr-h${fresh ? " sc-in" : ""}" style="--ph:${ph.toFixed(2)}s"><svg viewBox="0 0 120 72" class="sc-art" aria-hidden="true">${SCENE_SVG[k]}</svg>
      <div class="agr-t"><b>${esc(SCENE_NAME[k])}</b><span class="sc-meta"><span class="ai-clock" data-t0="${t0 || Date.now()}">${sceneClock(t0)}</span> · шаг ${g.length}</span></div>${stop}</div>
    <div class="agr-bar" aria-hidden="true"></div>
    ${hid ? `<div class="agr-more">раньше ещё: ${hid}</div>` : ""}
    <ol class="agr-list">${shown.map((it, i) => i === shown.length - 1
      ? `<li class="cur${step ? " in" : ""}"><span class="agr-dot" aria-hidden="true"></span><span>${esc(it.s)}${x(it.n)}</span></li>`
      : `<li><span class="agr-dot" aria-hidden="true">✓</span><span>${esc(it.s)}${x(it.n)}</span></li>`).join("")}</ol></div>`;
}
function sceneClock(t0){
  const s = Math.max(0, Math.floor((Date.now() - (t0 || Date.now())) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}
// время идёт само, без перерисовки окна
setInterval(() => document.querySelectorAll(".ai-clock[data-t0]").forEach(el => { el.textContent = sceneClock(+el.dataset.t0) }), 1000);
