// ============================================================ ЗДОРОВЬЕ ПК → ИСТОРИЯ
// Раз в сутки ScanHub записывает снимок: батарея, место на дисках, индекс стабильности, сбои. Здесь — как это менялось.
// Каждый показатель — свой график (одна линия, без второй оси); цвет — только у данных, подписи — обычным текстом.

const hNum = (v, d = 1) => v == null ? "—" : Number(v).toLocaleString(LOC, {maximumFractionDigits: d, minimumFractionDigits: 0});
const hDate = d => new Date(d + "T12:00:00").toLocaleDateString(LOC, {day: "numeric", month: "short", year: "2-digit"});
const hMonths = m => m >= 24 ? `${hNum(m / 12, 0)} лет` : m >= 12 ? "около года" : m >= 2 ? `${hNum(m, 0)} мес.` : "меньше двух месяцев";

// линия по датам: points [{d:"YYYY-MM-DD", v}], hover — ближайшая точка
function hLineChart(points, {min, max, fmt = v => hNum(v), unit = "", h = 150, band = null} = {}){
  const pts = points.filter(p => p.v != null);
  if (pts.length < 2) return `<div class="hchart-empty sub">${pts.length ? `Пока одна точка: ${esc(fmt(pts[0].v))}${unit}. График появится, когда накопится несколько дней.` : "Данных пока нет."}</div>`;
  const W = 600, H = h, L = 40, R = 10, T = 10, B = 22;
  const t = pts.map(p => new Date(p.d + "T12:00:00").getTime());
  const t0 = t[0], t1 = t.at(-1) === t0 ? t0 + 864e5 : t.at(-1);
  const lo = min ?? Math.min(...pts.map(p => p.v)), hi = max ?? Math.max(...pts.map(p => p.v));
  const pad = (hi - lo) * 0.08 || 1, y0 = min ?? lo - pad, y1 = max ?? hi + pad;
  const X = x => L + (x - t0) / (t1 - t0) * (W - L - R), Y = v => T + (1 - (v - y0) / (y1 - y0)) * (H - T - B);
  const ticks = [y0, (y0 + y1) / 2, y1];
  const path = pts.map((p, i) => `${i ? "L" : "M"}${X(t[i]).toFixed(1)},${Y(p.v).toFixed(1)}`).join("");
  const xl = [0, Math.floor((pts.length - 1) / 2), pts.length - 1].filter((v, i, a) => a.indexOf(v) === i);
  const data = attr(pts.map((p, i) => [X(t[i]), Y(p.v), hDate(p.d), fmt(p.v) + unit]));
  return `<div class="hchart" data-hpts="${data}"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="график" style="overflow:hidden">
      ${band && Math.min(band[1], y1) > Math.max(band[0], y0) ? `<rect x="${L}" width="${W - L - R}" y="${Y(Math.min(band[1], y1))}" height="${Y(Math.max(band[0], y0)) - Y(Math.min(band[1], y1))}" class="hband"/>` : ""}
      ${ticks.map(v => `<line x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}" class="hgrid"/><text x="${L - 6}" y="${Y(v) + 4}" class="hax" text-anchor="end">${esc(fmt(v))}</text>`).join("")}
      ${xl.map(i => `<text x="${X(t[i])}" y="${H - 6}" class="hax" text-anchor="${i === 0 ? "start" : i === pts.length - 1 ? "end" : "middle"}">${esc(hDate(pts[i].d))}</text>`).join("")}
      <path d="${path}" class="hline"/>
      <circle cx="${X(t.at(-1))}" cy="${Y(pts.at(-1).v)}" r="4" class="hdot"/>
      <line class="hcross" x1="0" x2="0" y1="${T}" y2="${H - B}" visibility="hidden"/><circle class="hmark" r="5" visibility="hidden"/>
    </svg><div class="htip" hidden></div></div>`;
}
// столбики по неделям: [{d (понедельник), v}]
function hBarChart(points, {fmt = v => hNum(v, 0), h = 120} = {}){
  if (!points.length) return `<div class="hchart-empty sub">Данных пока нет.</div>`;
  const W = 600, H = h, L = 30, R = 6, T = 8, B = 22, hi = Math.max(1, ...points.map(p => p.v));
  const bw = (W - L - R) / points.length, Y = v => T + (1 - v / hi) * (H - T - B);
  const data = attr(points.map((p, i) => [L + bw * i + bw / 2, Y(p.v), "неделя с " + hDate(p.d), fmt(p.v)]));
  return `<div class="hchart" data-hpts="${data}"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="столбики">
      <line x1="${L}" x2="${W - R}" y1="${Y(0)}" y2="${Y(0)}" class="hgrid"/><text x="${L - 6}" y="${Y(hi) + 4}" class="hax" text-anchor="end">${hi}</text>
      ${points.map((p, i) => p.v ? `<path class="hbar" d="M${L + bw * i + 2},${Y(0)} V${Y(p.v) + 4} q0,-4 4,-4 H${L + bw * (i + 1) - 6} q4,0 4,4 V${Y(0)} Z"/>` : "").join("")}
      ${[0, points.length - 1].map(i => `<text x="${L + bw * i + bw / 2}" y="${H - 6}" class="hax" text-anchor="middle">${esc(hDate(points[i].d))}</text>`).join("")}
      <line class="hcross" x1="0" x2="0" y1="${T}" y2="${H - B}" visibility="hidden"/><circle class="hmark" r="0" visibility="hidden"/>
    </svg><div class="htip" hidden></div></div>`;
}
document.addEventListener("mousemove", e => {
  const box = e.target.closest?.(".hchart");
  document.querySelectorAll(".hchart.hov").forEach(b => { if (b !== box) { b.classList.remove("hov"); b.querySelector(".htip").hidden = true;
    b.querySelectorAll(".hcross,.hmark").forEach(x => x.setAttribute("visibility", "hidden")) } });
  if (!box) return;
  const pts = JSON.parse(box.dataset.hpts || "[]"), svg = box.querySelector("svg"), r = svg.getBoundingClientRect();
  const x = (e.clientX - r.left) / r.width * 600;
  let k = 0;
  for (let i = 1; i < pts.length; i++) if (Math.abs(pts[i][0] - x) < Math.abs(pts[k][0] - x)) k = i;
  const [px, py, label, val] = pts[k];
  box.classList.add("hov");
  const cr = box.querySelector(".hcross"), mk = box.querySelector(".hmark"), tip = box.querySelector(".htip");
  cr.setAttribute("x1", px); cr.setAttribute("x2", px); cr.setAttribute("visibility", "visible");
  mk.setAttribute("cx", px); mk.setAttribute("cy", py); mk.setAttribute("visibility", "visible");
  tip.hidden = false; tip.innerHTML = `<b>${esc(val)}</b><span>${esc(label)}</span>`;
  const left = px / 600 * r.width;
  tip.style.left = Math.min(Math.max(0, left - 60), r.width - 130) + "px";
  tip.style.top = Math.max(0, py / svg.viewBox.baseVal.height * r.height - 52) + "px";
});

function hWeekly(days){
  const wk = {};
  for (const x of days) {
    const dt = new Date(x.d + "T12:00:00"), mon = new Date(dt - ((dt.getDay() + 6) % 7) * 864e5).toISOString().slice(0, 10);
    const e = x.events || {};
    wk[mon] = (wk[mon] || 0) + (e.crashes || 0) + (e.hangs || 0) + (e.bsod || 0) + (e.shutdowns || 0) + (e.gpu || 0);
  }
  return Object.keys(wk).sort().map(d => ({d, v: wk[d]}));
}

function pHistory(dev){
  const t = TASK.health_history, r = t?.result;
  const right = `<button data-task-run="health_history" data-args="${attr({force: true})}" ${t?.status === "running" ? "disabled" : ""}>Записать сейчас</button>`;
  const intro = explain("Раз в сутки ScanHub записывает состояние компьютера: ёмкость батареи, место на дисках, индекс стабильности Windows и сбои. Здесь видно, что постепенно ухудшается и как быстро — чтобы заменить батарею или освободить место до того, как станет плохо. Запись делается при открытии ScanHub или Сторожем, без постоянной работы в фоне. Данные хранятся только на этом компьютере.");
  if (!r) return pnl(head("История здоровья", "как менялось состояние компьютера", right) + intro + busyErr("health_history", "Собираю историю…"));
  const T = Object.fromEntries((r.trends || []).filter(x => x.what === "battery").map(x => ["battery", x]));
  const disks = (r.trends || []).filter(x => x.what === "disk");
  const lastBat = [...r.days].reverse().find(x => x.battery)?.battery;
  const parts = [];
  // батарея
  const b = T.battery;
  if (b) {
    const per = b.per_month_all ?? b.per_month;
    const verdict = b.now >= 80 ? "хорошо" : b.now >= 70 ? "заметно изношена" : "пора думать о замене";
    parts.push(`<div class="hcard"><div class="hhead"><div><h4>Ёмкость батареи</h4><div class="sub">сколько заряда вмещает сейчас по сравнению с новой</div></div>
        <div class="hstat"><b>${hNum(b.now)}%</b><span>${esc(verdict)}${lastBat?.cycles ? ` · ${lastBat.cycles} циклов зарядки` : ""}</span></div></div>
      ${hLineChart(r.battery.map(x => ({d: x.d, v: x.pct})), {unit: "%", band: [0, 70]})}
      <div class="sub">${b.first_d ? `С ${esc(hDate(b.first_d))}: было ${hNum(b.first)}%, стало ${hNum(b.now)}%. ` : ""}${per != null && per < -0.05 ? `Теряет около ${hNum(-per, 2)}% в месяц.` : "Почти не меняется."}
        ${b.months_to_70 ? ` До 70% (тогда ноутбук заметно меньше работает без зарядки) — примерно ${hMonths(b.months_to_70)}.` : ""}
        ${Math.min(...r.battery.map(x => x.pct)) < 78 ? "Цветная полоса внизу — ниже 70%, тогда батарею обычно меняют." : "Ниже 70% батарею обычно меняют."}</div></div>`);
  }
  // место на дисках — по графику на каждый диск
  for (const d of disks) {
    const pts = r.days.filter(x => x.disks?.[d.disk]).map(x => ({d: x.d, v: x.disks[d.disk].free}));
    const pct = d.total ? Math.round(d.now / d.total * 100) : null;
    parts.push(`<div class="hcard"><div class="hhead"><div><h4>Свободно на диске ${esc(d.disk)}</h4><div class="sub">из ${hNum(d.total, 0)} ГБ</div></div>
        <div class="hstat"><b>${hNum(d.now)} ГБ</b><span>${pct != null ? `${pct}% свободно` : ""}</span></div></div>
      ${hLineChart(pts, {unit: " ГБ", min: 0})}
      <div class="sub">${d.per_month == null ? `Тренд появится примерно через неделю записей (сейчас дней: ${d.days}).`
        : d.per_month < -0.3 ? `Место уходит: около ${hNum(-d.per_month)} ГБ в месяц.${d.months_left != null ? ` При таком темпе диск заполнится примерно через ${hMonths(d.months_left)}.` : ""}`
        : d.per_month > 0.3 ? `Места становится больше: +${hNum(d.per_month)} ГБ в месяц.` : "Почти не меняется."}
        ${pct != null && pct < 15 ? ` <a data-go-page="disk:disk">Что занимает место</a>` : ""}</div></div>`);
  }
  // стабильность и сбои
  const stab = r.days.filter(x => x.stability != null).map(x => ({d: x.d, v: x.stability}));
  if (stab.length) parts.push(`<div class="hcard"><div class="hhead"><div><h4>Индекс стабильности Windows</h4><div class="sub">от 1 до 10: Windows снижает его после сбоев и неудачных установок</div></div>
      <div class="hstat"><b>${hNum(stab.at(-1).v)}</b><span>из 10</span></div></div>${hLineChart(stab, {min: 0, max: 10})}
      <div class="sub">Падение — значит, в эти дни что-то вылетало или не ставилось. Подробности — в <a data-go-page="health:crash">«Сбоях и ошибках»</a>.</div></div>`);
  const wk = hWeekly(r.days);
  if (wk.length) parts.push(`<div class="hcard"><div class="hhead"><div><h4>Сбои по неделям</h4><div class="sub">вылеты и зависания программ, синие экраны, внезапные выключения, сбои видеодрайвера</div></div>
      <div class="hstat"><b>${wk.at(-1).v}</b><span>на этой неделе</span></div></div>${hBarChart(wk)}</div>`);
  return pnl(`${head("История здоровья", r.since ? `записи с ${esc(hDate(r.since))}` : "", right)}${intro}${busyErr("health_history", "Записываю…")}
    <div class="hgridwrap">${parts.join("") || `<div class="note info">Пока нечего показать — первая запись появится через минуту после запуска ScanHub.</div>`}</div>`);
}
