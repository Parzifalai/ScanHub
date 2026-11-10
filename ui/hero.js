// ============================================================ ГЛАВНАЯ: живой щит и показатели компьютера
// Щит строится один раз, дальше меняются только его переменные и подписи — так переходы между состояниями
// (синий → жёлтый → красный, ход проверки, вспышка в конце) идут плавно, а наклон за мышью не сбрасывается.
// Состояние честное: «Всё в порядке» — только когда защита Windows работает и в «Что стоит сделать» нет замечаний.

const HERO = {kind: null, scanning: false, flashT: 0};
const RING_C = 2 * Math.PI * 132;

// подписи щита собираются из чисел и слов — словарь en.json переводит кусками, поэтому английский пишется здесь же
const L = (ru, en) => LANG === "en" ? en : ru;
function heroScan(){
  const prog = steps => { const n = steps?.length || 0, d = (steps || []).filter(s => s.status === "done" || s.status === "skipped").length;
                          return n ? Math.min(.99, (d + .35) / n) : null };
  const uj = typeof ULTRA !== "undefined" ? ULTRA.job : null, dj = typeof DEEP !== "undefined" ? DEEP.data : null;
  if (uj?.status === "running") return {name: L("Ультра проверка", "Ultra scan"), f: prog(uj.steps), go: "scan:ultra"};
  if (dj?.status === "running") return {name: L("Глубокая проверка", "Deep scan"), f: prog(dj.steps), go: "scan:deep"};
  const b = simpleBatch && batches[simpleBatch];
  if (b) {
    const rows = b.jobs.map(id => openJobs.find(j => j.id === id)).filter(Boolean), run = rows.filter(r => r.status === "running").length;
    if (run) return {name: b.quick ? L("Быстрая проверка", "Quick scan") : L("Проверка файла", "File check"), f: b.quick ? null : (rows.length - run + .3) / rows.length, go: "scan:check"};
  }
  return null;
}

function heroState(){
  const sys = tool("defender")?.system, scan = heroScan();
  const bad = TODO.filter(x => x.lvl === "bad"), warn = TODO.filter(x => x.lvl === "warn" && !x.app);
  const last = HISTORY.find(h => h.batch || h.tool === "defender" || h.tool === "ultra" || h.tool === "deep");
  const lastTxt = last ? L(` Последняя проверка — ${ago(last.started)}.`, ` Last scan: ${ago(last.started)}.`) : L(" Проверок ещё не было.", " No scans yet.");
  const lastClean = last && ["clean", "unknown"].includes(last.verdict?.[0]);
  const ultra = {t: L("Ультра проверка", "Ultra scan"), s: L("всё сразу, около 40 минут", "everything at once, about 40 min"), attr: `data-go-page="scan:ultra"`, ic: "ultra"};
  if (scan) {
    const pct = scan.f != null ? Math.round(scan.f * 100) : null;
    return {kind: "scan", scan, title: L("Идёт проверка", "Scanning"),
      sub: `${scan.name}${pct != null ? ` — ${pct}%` : ""}. ` + L("Окно можно свернуть: ScanHub напишет, когда закончит.", "You can minimise the window — ScanHub will tell you when it's done."),
      btn: {t: L("Открыть ход проверки", "Show progress"), s: pct != null ? L(`готово ${pct}%`, `${pct}% done`) : L("можно свернуть окно", "you can minimise the window"), attr: `data-go-page="${scan.go}"`, ic: "scan"}};
  }
  if (sys?.realtime === false) return {kind: "bad", title: L("Защита выключена", "Protection is off"),
    sub: L("Защита в реальном времени Microsoft Defender отключена — компьютер не защищён от новых вирусов.", "Microsoft Defender real-time protection is off — the PC isn't protected from new viruses."),
    btn: {t: L("Включить защиту", "Turn protection on"), s: L("откроется «Безопасность Windows»", "opens Windows Security"), attr: `data-launch="threatsettings"`, ic: "scan"}};
  if (bad.length) {
    const threat = bad.find(x => /вирус|угроз|троян|вредонос|майнер|следил/i.test(x.t + " " + (x.s || "")));
    return {kind: "bad", title: threat ? L("Найдена угроза", "Threat found") : L("Нужно вмешаться", "Needs your attention"),
      sub: (threat || bad[0]).t + (bad.length > 1 ? L(` И ещё ${bad.length - 1} — ниже.`, ` And ${bad.length - 1} more below.`) : ""),
      btn: {t: L("Показать, что нашлось", "Show what was found"), s: L("список ниже", "list below"), attr: `data-hero-todo`, ic: "scan"}};
  }
  if (sys && (Date.now() - new Date(sys.updated)) / 864e5 > 3) return {kind: "warn", title: L("Базы антивируса устарели", "Antivirus definitions are old"),
    sub: L(`Microsoft Defender обновлял базы ${ago(sys.updated)}. Новые вирусы он может не узнать.`, `Microsoft Defender last updated ${ago(sys.updated)}. It may miss new viruses.`),
    btn: {t: L("Обновить базы", "Update definitions"), s: L("Microsoft Defender, около минуты", "Microsoft Defender, about a minute"), attr: `data-run="defender" data-mode="sigupdate"`, ic: "quick"}};
  if (warn.length) {
    const n = warn.length;
    return {kind: "warn", title: lastClean ? L("Вирусов не найдено", "No viruses found") : L("Защита включена", "Protection is on"),
      sub: L(`Но ${n} ${plural(n, "вещь", "вещи", "вещей")} стоит поправить — ${n === 1 ? "она" : "они"} ниже.`, `But ${n} ${n === 1 ? "thing is" : "things are"} worth fixing — see below.`) + lastTxt, btn: ultra};
  }
  if (!sys) return {kind: "idle", title: L("Проверяю защиту…", "Checking protection…"), sub: L("Смотрю, как работает защита Windows и что нашли прошлые проверки.", "Looking at Windows protection and what past scans found."), btn: ultra};
  return {kind: "ok", title: L("Всё в порядке", "All good"), sub: L("Защита Windows работает, базы свежие, замечаний нет.", "Windows protection is on, definitions are fresh, nothing to fix.") + lastTxt, btn: ultra};
}
function plural(n, one, few, many){ const a = n % 10, b = n % 100; return a === 1 && b !== 11 ? one : a >= 2 && a <= 4 && (b < 12 || b > 14) ? few : many }

const MARKS = {
  ok: '<path class="mk" pathLength="1" d="m52 90 20 20 38-40" fill="none" stroke="url(#shMarkG)" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/>',
  idle: '<path class="mk" pathLength="1" d="m52 90 20 20 38-40" fill="none" stroke="url(#shMarkG)" stroke-width="14" stroke-linecap="round" stroke-linejoin="round" opacity=".55"/>',
  warn: '<path class="mk" pathLength="1" d="m52 90 20 20 38-40" fill="none" stroke="url(#shMarkG)" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/>' +
        '<g class="badge"><circle cx="128" cy="146" r="20" fill="#F2A93B" stroke="#0A1124" stroke-width="4"/><path d="M128 135v12" stroke="#2A1A02" stroke-width="4.5" stroke-linecap="round"/><circle cx="128" cy="155" r="2.8" fill="#2A1A02"/></g>',
  bad: '<path class="mk" pathLength="1" d="M80 54v44" stroke="url(#shMarkG)" stroke-width="14" stroke-linecap="round"/><circle class="mk-dot" cx="80" cy="120" r="8.5" fill="#fff"/>',
  scan: '<text class="pct" x="80" y="104" text-anchor="middle"></text>',
};

function shieldMarkup(){
  const face = "M80 20C97 28 116 33 133 35V83C133 121 110 148 80 163C50 148 27 121 27 83V35C44 33 63 28 80 20Z";
  return `<div class="shield-wrap" aria-hidden="true">
    <div class="halo"></div><div class="disc"></div>
    <svg class="rings" viewBox="0 0 280 280">
      <circle cx="140" cy="140" r="132" class="r-base"/>
      <g class="r-spin"><circle cx="140" cy="140" r="132" class="r-arc" stroke-dasharray="150 680"/>
        <circle cx="140" cy="140" r="132" class="r-arc r-arc2" stroke-dasharray="40 790" stroke-dashoffset="-430"/>
        <circle cx="272" cy="140" r="4.5" class="r-dot"/><circle cx="30" cy="92" r="3" class="r-dot" opacity=".7"/><circle cx="96" cy="264" r="2" fill="#fff" opacity=".6"/></g>
      <circle cx="140" cy="140" r="112" class="r-dash"/>
      <circle cx="140" cy="140" r="132" class="r-prog" stroke-dasharray="${RING_C.toFixed(1)}" stroke-dashoffset="${RING_C.toFixed(1)}" transform="rotate(-90 140 140)"/>
    </svg>
    <div class="shield-tilt"><svg class="shield" viewBox="0 0 160 184">
      <defs>
        <linearGradient id="shRim" x1="0" y1="0" x2="1" y2="1"><stop offset="0" style="stop-color:var(--s1)"/><stop offset=".45" style="stop-color:var(--s2)"/><stop offset="1" style="stop-color:var(--s3)"/></linearGradient>
        <radialGradient id="shFace" cx=".32" cy=".22" r=".95"><stop offset="0" style="stop-color:var(--f1)"/><stop offset=".5" style="stop-color:var(--f2)"/><stop offset="1" style="stop-color:var(--f3)"/></radialGradient>
        <linearGradient id="shGloss" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".55"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient>
        <linearGradient id="shMarkG" gradientUnits="userSpaceOnUse" x1="0" y1="50" x2="0" y2="130"><stop offset="0" stop-color="#fff"/><stop offset="1" stop-color="#DCE7FF"/></linearGradient>
        <linearGradient id="shBeam" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#9CC2FF" stop-opacity="0"/><stop offset=".7" stop-color="#BFD6FF" stop-opacity=".55"/><stop offset="1" stop-color="#fff" stop-opacity=".9"/></linearGradient>
        <radialGradient id="shGlint"><stop offset="0" stop-color="#fff" stop-opacity=".5"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></radialGradient>
        <filter id="shMarkShadow" x="-30%" y="-30%" width="160%" height="160%"><feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#041033" flood-opacity=".55"/></filter>
        <clipPath id="shFaceClip"><path d="${face}"/></clipPath>
      </defs>
      <path d="M80 6C100 16 124 22 146 24V82C146 128 118 160 80 178C42 160 14 128 14 82V24C36 22 60 16 80 6Z" fill="url(#shRim)"/>
      <path d="M80 6C100 16 124 22 146 24V82C146 128 118 160 80 178" fill="none" stroke="rgba(0,0,0,.25)" stroke-width="2"/>
      <path d="${face}" fill="url(#shFace)"/>
      <g clip-path="url(#shFaceClip)">
        <rect x="80" y="0" width="80" height="184" fill="#000" opacity=".16"/>
        <ellipse cx="62" cy="40" rx="48" ry="28" fill="url(#shGloss)" opacity=".7"/>
        <rect class="beam" x="0" y="-30" width="160" height="30" fill="url(#shBeam)"/>
        <circle class="glint" cx="60" cy="50" r="46" fill="url(#shGlint)"/>
      </g>
      <path d="${face}" fill="none" stroke="rgba(255,255,255,.4)" stroke-width="1.2"/>
      <g class="mark" filter="url(#shMarkShadow)"></g>
    </svg></div>
  </div>`;
}

function renderHero(){
  const box = $("#hero");
  if (!box) return;
  if (!box.querySelector(".shield-wrap")) {
    box.innerHTML = `${shieldMarkup()}<div class="hero-text"><h2 id="heroTitle"></h2><p id="heroSub"></p>
      <div class="hero-actions"><button class="primary big" id="heroBtn"></button>
        <button class="round" id="heroMore" aria-label="Другие проверки" aria-haspopup="true" aria-expanded="false">${icon("more")}</button>
        <div class="hero-menu" id="heroMenu" hidden>
          <button data-act="quick">${icon("quick")}<span><b>Быстрая проверка</b><span>Defender: память, автозагрузка и системные папки. 2–5 минут</span></span></button>
          <button data-go-page="scan:deep">${icon("deep")}<span><b>Глубокая проверка</b><span>Все сканеры по очереди. 15–40 минут</span></span></button>
          <button data-act="pick">${icon("file")}<span><b>Проверить файл или папку</b><span>Скачанную программу, «Загрузки», флешку</span></span></button>
        </div></div></div>`;
    heroTilt(box.querySelector(".shield-wrap"));
  }
  const st = heroState(), wrap = box.querySelector(".shield-wrap");
  const kindChanged = st.kind !== HERO.kind;
  if (kindChanged) {
    if (HERO.kind === "scan" && st.kind !== "scan") { wrap.classList.remove("flash"); void wrap.offsetWidth; wrap.classList.add("flash") }  // проверка закончилась — вспышка
    HERO.kind = st.kind;
    wrap.dataset.state = st.kind;
    box.dataset.state = st.kind;
    wrap.querySelector(".mark").innerHTML = MARKS[st.kind];       // заново — чтобы знак нарисовался штрихом
  }
  if (st.kind === "scan") {
    const f = st.scan.f;
    wrap.querySelector(".r-prog").style.strokeDashoffset = f == null ? RING_C * .75 : RING_C * (1 - f);
    wrap.classList.toggle("indet", f == null);
    const t = wrap.querySelector(".pct");
    if (t) t.textContent = f == null ? "…" : Math.round(f * 100) + "%";
  }
  const set = (sel, v) => { const el = $(sel); if (el && el.textContent !== v) el.textContent = v };
  set("#heroTitle", st.title);
  set("#heroSub", st.sub);
  const b = $("#heroBtn"), html = `${icon(st.btn.ic)}<span class="ttl">${esc(st.btn.t)}<small>${esc(st.btn.s)}</small></span>`;
  if (b.dataset.html !== html) {
    b.dataset.html = html; b.innerHTML = html;
    [...b.attributes].filter(a => /^data-(go-page|run|mode|launch|hero-todo)$/.test(a.name)).forEach(a => b.removeAttribute(a.name));
    st.btn.attr.replace(/([\w-]+)(?:="([^"]*)")?/g, (_, k, v) => b.setAttribute(k, v ?? ""));
    b.classList.toggle("danger-fill", st.kind === "bad");
  }
}

// наклон и блик за мышью: только у щита, мягко возвращается на место
function heroTilt(wrap){
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const tilt = wrap.querySelector(".shield-tilt"), glint = wrap.querySelector(".glint");
  let raf = 0;
  wrap.addEventListener("pointermove", e => {
    const r = wrap.getBoundingClientRect(), x = (e.clientX - r.left) / r.width - .5, y = (e.clientY - r.top) / r.height - .5;
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(() => {
      tilt.style.transform = `perspective(700px) rotateX(${(-y * 16).toFixed(2)}deg) rotateY(${(x * 18).toFixed(2)}deg)`;
      glint.setAttribute("cx", (80 + x * 110).toFixed(1)); glint.setAttribute("cy", (90 + y * 120).toFixed(1));
      wrap.classList.add("hover");
    });
  });
  wrap.addEventListener("pointerleave", () => { cancelAnimationFrame(raf); tilt.style.transform = ""; wrap.classList.remove("hover") });
}

document.addEventListener("click", e => {
  const more = e.target.closest("#heroMore"), menu = $("#heroMenu");
  if (more) { menu.hidden = !menu.hidden; more.setAttribute("aria-expanded", String(!menu.hidden)); return }
  if (menu && !menu.hidden && !e.target.closest("#heroMenu")) { menu.hidden = true; $("#heroMore")?.setAttribute("aria-expanded", "false") }
  if (e.target.closest("[data-hero-todo]")) $("#todo")?.scrollIntoView({behavior: "smooth", block: "start"});
  const qm = e.target.closest("#qaMore");
  if (qm) { const m = $("#quickMore"); m.hidden = !m.hidden; qm.textContent = m.hidden ? "Все быстрые действия" : "Свернуть"; qm.setAttribute("aria-expanded", String(!m.hidden)) }
});
document.addEventListener("keydown", e => { if (e.key === "Escape" && $("#heroMenu") && !$("#heroMenu").hidden) { $("#heroMenu").hidden = true; $("#heroMore")?.focus() } });
// пока идёт проверка — щит следит за ходом сам (раз в 1,5 с; данные уже собирают опросы ультра/глубокой/файла)
setInterval(() => { if (PAGE === "home" && !document.hidden && (HERO.kind === "scan" || heroScan())) renderHero() }, 1500);

// ---------- показатели справа от щита: нажатие открывает «Скорость и игры → Нагрузка сейчас»
function hSpark(values, color, max = 100){
  const v = (values || []).slice(-40);
  if (v.length < 2) return `<svg class="hsp" viewBox="0 0 200 34"></svg>`;
  const pts = v.map((y, i) => [i * 200 / (v.length - 1), 32 - Math.min(1, (y ?? 0) / max) * 28]);
  const d = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const id = "hg" + color.replace(/\W/g, "");
  return `<svg class="hsp" viewBox="0 0 200 34" preserveAspectRatio="none"><defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${color}" stop-opacity=".32"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
    <path d="${d} L200 34 L0 34Z" fill="url(#${id})"/><path d="${d}" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>
    <circle cx="${pts.at(-1)[0]}" cy="${pts.at(-1)[1]}" r="3" fill="${color}"/></svg>`;
}
function homeStats(){
  const el = $("#hStats");
  if (!el || !M?.series) return;
  const S = M.series, now = M.now, st = M.static, g = M.gpu;
  const cpu = last(S.cpu), ramU = now.ram_used, ramT = now.ram_total || st.ram_total;
  const sys = (now.disks || []).find(d => /^c:/i.test(d.mount)) || (now.disks || [])[0];
  const stab = TASK.diag?.result?.stability || [], sv = stab.at(-1)?.v;
  const tiles = [];
  if (sv != null) {
    const [lvl] = stabVerdict(sv);
    tiles.push(`<div class="hs ${lvl === "ok" ? "" : lvl}"><span class="k">${icon("health")}Стабильность Windows</span><b class="v">${sv.toFixed(1).replace(".", ",")}<small>из 10</small></b>
      <span class="n">${esc(stabVerdict(sv)[1])}</span>${hSpark(stab.slice(-28).map(x => x.v), "#5B8CFF", 10)}</div>`);
  } else if (g) {
    tiles.push(`<div class="hs"><span class="k">${icon("game")}Видеокарта</span><b class="v">${Math.round(g.util ?? 0)}<small>%${g.temp != null ? ` · ${g.temp}°C` : ""}</small></b>
      <span class="n">${esc(g.name || "")}</span>${hSpark(S.gpu, "#7BA3FF")}</div>`);
  }
  tiles.push(`<div class="hs"><span class="k">${icon("chip")}Процессор</span><b class="v">${Math.round(cpu ?? 0)}<small>%${M.sensors?.cpu_temp ? ` · ${Math.round(M.sensors.cpu_temp)}°C` : ""}</small></b>
    <span class="n">${cpu < 15 ? L("почти не нагружен", "barely loaded") : cpu < 60 ? L("обычная нагрузка", "normal load") : L("нагружен сильно", "heavily loaded")}</span>${hSpark(S.cpu, "#7BA3FF")}</div>`);
  tiles.push(`<div class="hs"><span class="k">${icon("ram")}Оперативная память</span><b class="v">${Math.round(ramU / ramT * 100)}<small>%</small></b>
    <span class="n">${L(`${(ramU / GB).toFixed(1).replace(".", ",")} из ${(ramT / GB).toFixed(0)} ГБ занято`, `${(ramU / GB).toFixed(1)} of ${(ramT / GB).toFixed(0)} GB in use`)}</span>${hSpark(S.ram, "#34C98A")}</div>`);
  if (sys) {
    const free = sys.total - sys.used, pct = sys.percent, low = pct >= 87;
    tiles.push(`<div class="hs ${pct >= 93 ? "bad" : low ? "warn" : ""}"><span class="k">${icon("disk")}Свободно на диске ${esc(sys.mount.replace(/\\$/, ""))}</span>
      <b class="v">${fmtB(free).replace(/\s?(ГБ|МБ|ТБ)$/, "")}<small>${(fmtB(free).match(/(ГБ|МБ|ТБ)$/) || [""])[0]} из ${fmtB(sys.total)}</small></b>
      <span class="n">${pct >= 90 ? L("места почти нет — Windows уже может тормозить", "almost full — Windows may already slow down") : low ? L(`${Math.round(100 - pct)}% свободно — при 10% Windows начнёт тормозить`, `${Math.round(100 - pct)}% free — Windows slows down below 10%`) : L(`занято ${Math.round(pct)}%`, `${Math.round(pct)}% used`)}</span>
      <span class="hbar"><i style="width:${pct}%"></i></span></div>`);
  }
  el.innerHTML = tiles.slice(0, 4).join("") + `<span class="hs-go">${L("Нагрузка подробно", "Load in detail")} ${icon("arrow")}</span>`;
}
