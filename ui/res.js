// ============================================================ РЕСУРСЫ
let M = null, procSort = "cpu";
const hover = {};                    // id графика -> индекс точки под курсором
const GB = 1024 ** 3;
const fmtB = b => b == null ? "—" : b >= GB ? (b / GB).toFixed(1) + " ГБ" : b >= 2 ** 20 ? (b / 2 ** 20).toFixed(0) + " МБ" : (b / 1024).toFixed(0) + " КБ";
const fmtRate = b => b == null ? "—" : b >= 2 ** 20 ? (b / 2 ** 20).toFixed(1) + " МБ/с" : (b / 1024).toFixed(0) + " КБ/с";
const fmtPct = v => v == null ? "—" : Math.round(v) + "%";
const fmtUp = s => { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return (d ? d + " д " : "") + h + " ч " + m + " мин" };
const last = a => a?.length ? a[a.length - 1] : null;
function niceMax(vals, floor){
  const m = Math.max(floor, ...vals.filter(v => v != null));
  const p = 10 ** Math.floor(Math.log10(m)), n = m / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

function spark(values, color, max = 100){
  const v = values.slice(-60), w = 100, h = 30;
  if (v.length < 2) return "";
  const pts = v.map((y, i) => `${(i / (v.length - 1) * w).toFixed(1)},${(h - 2 - (y ?? 0) / max * (h - 4)).toFixed(1)}`).join(" ");
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/></svg>`;
}

// линейный график: одна ось, общая единица; перекрестие + подсказка со всеми сериями
function lineChart(...a){ try { lineChartInner(...a) } catch (e) { console.error("chart", a[0], e) } }
function lineChartInner(id, title, series, t, {max, fmt, axisFmt, extra}){
  const el = document.getElementById(id);
  if (!el) return;
  const W = Math.max(200, el.clientWidth - 28), H = 150, L = 44, B = 18, n = t.length;
  const x = i => L + (n <= 1 ? 0 : i / (HISTORY_LEN - 1) * (W - L)) + (HISTORY_LEN - n) / (HISTORY_LEN - 1) * (W - L);
  const y = v => (H - B) - (v ?? 0) / max * (H - B - 6);
  const grid = [0, .5, 1].map(f => `<line x1="${L}" x2="${W}" y1="${y(max * f)}" y2="${y(max * f)}" stroke="var(--grid)" stroke-width="1"/>
     <text class="axis" x="${L - 6}" y="${y(max * f) + 3.5}" text-anchor="end">${axisFmt(max * f)}</text>`).join("");
  const xl = [[0, "5 мин"], [.5, "2,5 мин"], [1, "сейчас"]].map(([f, s]) => `<text class="axis" x="${L + f * (W - L)}" y="${H - 3}" text-anchor="${f === 0 ? "start" : f === 1 ? "end" : "middle"}">${s}</text>`).join("");
  const lines = series.map(s => {
    const pts = s.values.map((v, i) => v == null ? null : `${x(i).toFixed(1)},${y(v).toFixed(1)}`).filter(Boolean).join(" ");
    const area = series.length === 1 && pts ? `<polygon points="${x(0)},${y(0)} ${pts} ${x(n - 1)},${y(0)}" fill="${s.color}" opacity=".10"/>` : "";
    return `${area}<polyline points="${pts}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
  }).join("");
  let cross = "", tip = "";
  const hi = hover[id];
  if (hi != null && hi < n) {
    cross = `<line x1="${x(hi)}" x2="${x(hi)}" y1="6" y2="${H - B}" stroke="var(--muted)" stroke-width="1" stroke-dasharray="3 3"/>` +
      series.map(s => s.values[hi] == null ? "" : `<circle cx="${x(hi)}" cy="${y(s.values[hi])}" r="4" fill="${s.color}" stroke="var(--panel)" stroke-width="2"/>`).join("");
    const ago = n - 1 - hi;
    tip = `<div class="tip" style="left:${Math.min(x(hi) + 22, W - 120)}px;top:34px">
      <div class="sub" style="margin-bottom:3px">${ago ? ago + " с назад" : "сейчас"}</div>
      ${series.map(s => `<div><span class="sw" style="background:${s.color}"></span><b>${esc(fmt(s.values[hi]))}</b> <span class="sub">${esc(s.label)}</span></div>`).join("")}
      ${extra ? `<div class="sub" style="margin-top:3px">${esc(extra(hi))}</div>` : ""}</div>`;
  }
  el.innerHTML = `<h4>${title}</h4>
    ${series.length > 1 ? `<div class="legend">${series.map(s => `<span><i style="background:${s.color}"></i>${esc(s.label)} ${esc(fmt(last(s.values)))}</span>`).join("")}</div>`
                        : `<div class="legend"><span>сейчас ${esc(fmt(last(series[0].values)))}</span></div>`}
    <svg viewBox="0 0 ${W} ${H}" data-chart="${id}" data-l="${L}" data-w="${W}" data-n="${n}">${grid}${xl}${lines}${cross}
      <rect x="${L}" y="0" width="${W - L}" height="${H - B}" fill="transparent"/></svg>${tip}`;
}
const HISTORY_LEN = 300;
document.addEventListener("pointermove", e => {
  const svg = e.target.closest?.("svg[data-chart]");
  const prev = Object.keys(hover).find(k => hover[k] != null);
  if (!svg) { if (prev) { hover[prev] = null; drawRes() } return }
  const r = svg.getBoundingClientRect(), W = +svg.dataset.w, L = +svg.dataset.l, n = +svg.dataset.n;
  const px = (e.clientX - r.left) / r.width * W;
  const offset = (HISTORY_LEN - n) / (HISTORY_LEN - 1) * (W - L);
  let i = Math.round((px - L - offset) / (W - L) * (HISTORY_LEN - 1));
  i = Math.max(0, Math.min(n - 1, i));
  if (prev && prev !== svg.dataset.chart) hover[prev] = null;
  if (hover[svg.dataset.chart] !== i) { hover[svg.dataset.chart] = i; drawRes() }
});

function procActions(p, simple){
  const witr = tool("witr")?.ready;
  return `${p.exe ? `<a data-scan-exe="${esc(p.exe)}">${simple ? "Проверить файл" : "проверить"}</a>` : ""}
    ${p.exe ? `<a data-open="${esc(p.exe)}">${simple ? "Открыть папку" : "папка"}</a>` : ""}
    ${!simple && witr ? `<a data-why="${p.pid}">почему?</a>` : ""}
    ${!simple ? `<a data-kill="${p.pid}" data-name="${esc(p.name)}" style="color:var(--bad)">завершить</a>` : ""}`;
}
function alertHtml(sus, simple){
  if (!sus?.length) return "";
  return `<div class="alert"><b>⚠ ${sus.length === 1 ? "Подозрительный процесс" : "Подозрительные процессы"} — похоже на скрытый майнер</b>
    ${sus.map(p => `<div class="p"><b style="color:var(--text)">${esc(p.name)}</b> ${simple ? "" : `(PID ${p.pid}) `}— ${esc(p.flags.join("; "))}.
      Процессор ${fmtPct(p.cpu_avg)} в среднем${p.gpu_mem ? `, видеопамять ${p.gpu_mem} МБ` : ""}.
      ${p.exe ? `<div class="sub" style="font-family:var(--mono)">${esc(p.exe)}</div>` : ""}
      <div class="acts" style="margin-top:4px">${procActions(p, simple).replace(/<a /g, '<a class="small" ')}</div></div>`).join("")}
    ${simple ? `<div class="p">Совет: проверь файл, а затем запусти MinerSearch или KVRT из списка ниже.</div>` : ""}</div>`;
}

function drawRes(){
  try { drawResInner() } catch (e) { console.error("drawRes", e) }
}
function safe(fn){ try { fn() } catch (e) { console.error(e) } }
function drawResInner(){
  if (!M || !M.series.cpu.length || !M.now.ram_used) return;     // сбор только начался
  const S = M.series, g = M.gpu, now = M.now, st = M.static;
  const ramUsed = now.ram_used, ramTot = now.ram_total || st.ram_total;
  if (PAGE === "home") {
    renderTodo();
    const top = M.top_cpu.filter(p => p.cpu >= 0.5).slice(0, 3);
    $("#sRes").innerHTML = `${alertHtml(M.suspicious, true)}
      <div class="kpis" style="${M.suspicious?.length ? "margin-top:12px" : ""}">
        <div class="kpi"><span class="k">Процессор</span><span class="v">${fmtPct(last(S.cpu))}${M.sensors?.cpu_temp ? `<small>${Math.round(M.sensors.cpu_temp)}°C</small>` : ""}</span>${spark(S.cpu, "var(--s1)")}</div>
        ${M.sensors?.fans?.length ? `<div class="kpi"><span class="k">Вентиляторы</span><span class="v" style="font-size:20px">${M.sensors.fans.map(f => Math.round(f)).join(" / ")}<small>об/мин</small></span><span class="s">${esc(fanLevel(M.sensors.fans))}${M.sensors.fan_mode ? " · режим " + esc(M.sensors.fan_mode) : ""}</span></div>` : ""}
        <div class="kpi"><span class="k">Память</span><span class="v">${(ramUsed / GB).toFixed(1)}<small>из ${(ramTot / GB).toFixed(0)} ГБ</small></span>${spark(S.ram, "var(--s1)")}</div>
        ${g ? `<div class="kpi"><span class="k">Видеокарта</span><span class="v">${fmtPct(g.util)}<small>${g.temp ?? "—"}°C</small></span>${spark(S.gpu, "var(--s1)")}</div>` : ""}
      </div>
      <div class="load">${top.length ? "Больше всего нагружают: " + top.map(p => `<b>${esc(p.name.replace(/\.exe$/i, ""))}</b> ${fmtPct(p.cpu)}`).join(", ") : "Компьютер почти не нагружен."}</div>
      ${cpuLine(M.cpu_why)}
      ${heatLine(M.heat)}
      ${memLine()}
      ${M.sensors_on === false && M.static?.lenovo_wmi ? `<div class="load"><a data-task-run="sensors_set" data-args='{"enable":true}'>Показать температуру процессора и скорость вентиляторов →</a> <span class="sub">(один раз попросит права администратора)</span></div>` : ""}`;
    return;
  }
  if (PAGE !== "res") { if (PAGE === "speed" && SUB === "memory") redrawPanels(); return }
  const sensBusy = TASK.sensors_set?.status === "running";
  const sensCard = M.sensors_on && M.sensors_outdated
    ? `<div class="note info" style="margin-bottom:12px;display:flex;gap:12px;align-items:center;flex-wrap:wrap"><span style="flex:1;min-width:240px">Есть новая версия агента датчиков: научился читать обороты вентиляторов на Lenovo LOQ / новых Legion. Обновление один раз попросит UAC.</span>
       <button class="primary small" data-task-run="sensors_set" data-args='{"enable":true}' ${sensBusy ? "disabled" : ""}>${sensBusy ? "Жду подтверждения UAC…" : "Обновить агента датчиков"}</button></div>`
    : !M.sensors_on && !M.static?.lenovo_wmi ? `<div class="note info" style="margin-bottom:12px">Температура процессора и обороты вентиляторов: на этом устройстве нет датчиков производителя, которые умеет читать ScanHub (пока поддерживаются Lenovo Legion / LOQ / IdeaPad Gaming). Видеокарта NVIDIA, нагрузка и всё остальное работают.</div>`
    : M.sensors_on ? (M.sensors ? "" : M.sensors_stuck
      ? `<div class="note warn" style="margin-bottom:12px;display:flex;gap:12px;align-items:center;flex-wrap:wrap"><span style="flex:1;min-width:240px">Агент датчиков не отвечает. Переустановка исправит настройки задачи (один раз попросит UAC).</span>
         <button class="small" data-task-run="sensors_set" data-args='{"enable":true}' ${sensBusy ? "disabled" : ""}>${sensBusy ? "Жду подтверждения UAC…" : "Переустановить датчики"}</button></div>`
      : `<div class="note info" style="margin-bottom:12px">Запускаю датчики Lenovo… (несколько секунд)</div>`)
    : `<div class="note info" style="margin-bottom:12px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
        <span style="flex:1;min-width:260px"><b>Температура процессора и скорость вентиляторов.</b> Датчики Lenovo доступны только с правами администратора:
        включение один раз попросит подтверждение (UAC), дальше всё работает само и только пока открыт ScanHub.</span>
        <button class="primary small" data-task-run="sensors_set" data-args='{"enable":true}' ${sensBusy ? "disabled" : ""}>${sensBusy ? "Жду подтверждения UAC…" : "Включить датчики"}</button></div>`;
  $("#resAlert").innerHTML = sensCard + (M.suspicious?.length ? alertHtml(M.suspicious, false) + "<div style='height:12px'></div>" : "") + (TASK.sensors_set?.error ? `<div class="note bad" style="margin-bottom:12px">${esc(TASK.sensors_set.error)}</div>` : "");
  const bat = now.battery;
  $("#resKpis").innerHTML = `
    <div class="kpi"><span class="k">Процессор</span><span class="v">${fmtPct(last(S.cpu))}${M.sensors?.cpu_temp ? `<small>${Math.round(M.sensors.cpu_temp)}°C</small>` : ""}</span><span class="s">${esc(st.cpu_name)}</span>${spark(S.cpu, "var(--s1)")}</div>
    ${M.sensors?.fans?.length ? `<div class="kpi"><span class="k">Вентиляторы</span><span class="v" style="font-size:20px">${M.sensors.fans.map(f => Math.round(f)).join(" / ")}<small>об/мин</small></span><span class="s">${esc(fanLevel(M.sensors.fans))}${M.sensors.fan_mode ? " · режим " + esc(M.sensors.fan_mode) : ""}</span>${spark(S.fan1, "var(--s1)", M.sensors.fan_max || 6000)}</div>` : ""}
    <div class="kpi"><span class="k">Память</span><span class="v">${(ramUsed / GB).toFixed(1)}<small>/ ${(ramTot / GB).toFixed(0)} ГБ</small></span><span class="s">файл подкачки ${fmtPct(now.swap)}</span>${spark(S.ram, "var(--s1)")}</div>
    ${g ? `<div class="kpi"><span class="k">Видеокарта</span><span class="v">${fmtPct(g.util)}<small>${g.temp ?? "—"}°C · ${g.power ?? "—"} Вт</small></span><span class="s">${esc(g.name)} · ${(g.mem_used / 1024).toFixed(1)}/${(g.mem_total / 1024).toFixed(0)} ГБ</span>${spark(S.gpu, "var(--s1)")}</div>` : ""}
    <div class="kpi"><span class="k">Сеть</span><span class="v" style="font-size:18px">↓ ${fmtRate(last(S.net_down))}</span><span class="s">↑ ${fmtRate(last(S.net_up))}</span></div>
    <div class="kpi"><span class="k">Диск</span><span class="v" style="font-size:18px">${fmtRate(last(S.disk_read))}</span><span class="s">чтение · запись ${fmtRate(last(S.disk_write))}</span></div>
    <div class="kpi"><span class="k">${bat ? "Батарея" : "Работает"}</span><span class="v" style="font-size:18px">${bat ? bat.percent + "%" : fmtUp(M.uptime)}</span><span class="s">${bat ? (bat.plugged ? "заряжается · " : "от батареи · ") + "вкл. " + fmtUp(M.uptime) : esc(st.host)}</span></div>`;
  let ml = $("#memLineDev");
  if (!ml) { ml = document.createElement("div"); ml.id = "memLineDev"; $("#resKpis").after(ml) }
  ml.innerHTML = memLine();
  if (!$("#c-cpu")) $("#resCharts").innerHTML = ["c-cpu", "c-ram", "c-gpu", "c-temp", "c-ctemp", "c-fans", "c-net", "c-disk"].map(i => `<div class="chart" id="${i}"></div>`).join("");
  const hasCT = S.cpu_temp?.some(v => v != null), hasFan = S.fan1?.some(v => v != null);
  $("#c-ctemp").hidden = !hasCT; $("#c-fans").hidden = !hasFan;
  if (hasCT) lineChart("c-ctemp", "Температура процессора, °C", [{label: "температура", color: "var(--s1)", values: S.cpu_temp}], S.t,
    {max: 100, fmt: v => v == null ? "—" : Math.round(v) + "°C", axisFmt: v => v + "°"});
  if (hasFan) lineChart("c-fans", "Вентиляторы, об/мин · меняются с задержкой 30–60 с, шаг 100", [{label: "вентилятор 1", color: "var(--s1)", values: S.fan1},
    ...(S.fan2?.some(v => v != null) ? [{label: "вентилятор 2", color: "var(--s2)", values: S.fan2}] : [])], S.t,
    {max: niceMax([...S.fan1, ...(S.fan2 || [])], 1000), fmt: v => v == null ? "—" : Math.round(v) + " об/мин", axisFmt: v => v >= 1000 ? (v / 1000) + "k" : v});
  const pct = {max: 100, fmt: fmtPct, axisFmt: v => v + "%"};
  const whoCpu = i => { const x = S.cpu_top?.[i]; return x ? `грузил: ${x[0].replace(/\.exe$/i, "")} ${Math.round(x[1])}%` : "никто заметно не грузил" };
  lineChart("c-cpu", "Процессор, %", [{label: "загрузка", color: "var(--s1)", values: S.cpu}], S.t, {...pct, extra: whoCpu});
  lineChart("c-ram", "Память, %", [{label: "занято", color: "var(--s1)", values: S.ram}], S.t, pct);
  if (g) {
    const who = i => { const x = S.gpu_top?.[i]; return x ? `грузил: ${x[0].replace(/\.exe$/i, "")} ${Math.round(x[1])}%` : "видеокарта почти простаивала" };
    lineChart("c-gpu", "Видеокарта, %", [{label: "загрузка", color: "var(--s1)", values: S.gpu}], S.t, {...pct, extra: who});
    lineChart("c-temp", "Температура видеокарты, °C", [{label: "температура", color: "var(--s1)", values: S.gpu_temp}], S.t,
      {max: 100, fmt: v => v == null ? "—" : Math.round(v) + "°C", axisFmt: v => v + "°", extra: who});
  } else { $("#c-gpu").hidden = $("#c-temp").hidden = true }
  const rateAxis = v => v >= 2 ** 20 ? (v / 2 ** 20).toFixed(v >= 10 * 2 ** 20 ? 0 : 1) + "M" : (v / 1024).toFixed(0) + "K";
  lineChart("c-net", "Сеть, в секунду", [{label: "загрузка", color: "var(--s1)", values: S.net_down}, {label: "отдача", color: "var(--s2)", values: S.net_up}], S.t,
    {max: niceMax([...S.net_down, ...S.net_up], 102400), fmt: fmtRate, axisFmt: rateAxis});
  lineChart("c-disk", "Диск, в секунду", [{label: "чтение", color: "var(--s1)", values: S.disk_read}, {label: "запись", color: "var(--s2)", values: S.disk_write}], S.t,
    {max: niceMax([...S.disk_read, ...S.disk_write], 1048576), fmt: fmtRate, axisFmt: rateAxis});
  safe(drawHeat);
  safe(drawCpuWhy);
  $("#coresSub").textContent = `${st.cores} ядер · ${st.threads} потоков`;
  $("#cores").innerHTML = M.percpu.map((v, i) => `<div style="height:${Math.max(2, v)}%" title="Поток ${i + 1}: ${Math.round(v)}%"></div>`).join("");
  $("#disks").innerHTML = (now.disks || []).map(d => `<div class="disk">
      <div class="row"><span><b>${esc(d.mount)}</b> ${esc(d.fs)}</span><span>${d.percent >= 90 ? '<b style="color:var(--crit)">⚠ мало места</b> · ' : ""}свободно ${fmtB(d.total - d.used)} из ${fmtB(d.total)}</span></div>
      <div class="bar" title="${d.percent}% занято"><div class="${d.percent >= 90 ? "crit" : ""}" style="width:${d.percent}%"></div></div></div>`).join("");
  const list = procSort === "cpu" ? M.top_cpu : M.top_mem, maxCpu = Math.max(1, ...list.map(p => p.cpu));
  $("#procCount").textContent = `всего ${M.count}`;
  $("#procs").innerHTML = `<tr><th>Процесс</th><th class="n">PID</th><th class="n">ЦП</th><th class="n">ЦП, ср.</th><th class="n">Память</th><th class="n">Видео</th><th>Путь</th><th></th></tr>` +
    list.map(p => `<tr${p.flags.length ? ' style="background:var(--bad-bg)"' : ""}>
      <td>${p.flags.length ? "⚠ " : ""}${esc(p.name)}${p.sig?.signer ? `<div class="sub" style="font-size:11px">${esc(p.sig.signer)}</div>` : ""}</td>
      <td class="n">${p.pid}</td>
      <td class="n">${p.cpu.toFixed(1)}%<span class="mini"><i style="width:${p.cpu / maxCpu * 100}%"></i></span></td>
      <td class="n">${p.cpu_avg.toFixed(1)}%</td><td class="n">${fmtB(p.mem)}</td><td class="n">${p.gpu_mem ? p.gpu_mem + " МБ" : ""}</td>
      <td class="path" title="${esc(p.exe)}">${esc(p.exe || "нет доступа")}</td>
      <td class="acts">${procActions(p, false)}</td></tr>`).join("");
  $("#resSys").innerHTML = `${esc(st.host)} · ${esc(st.os)} · данные за последние 5 минут, обновляются каждую секунду, пока открыта эта вкладка` +
    (M.sensors_on ? ` · датчики Lenovo включены (<a data-task-run="sensors_set" data-args='{"enable":false}'>выключить</a>)` : "");
}

function fanLevel(fans){
  const f = Math.max(...(fans || [0]));
  return f === 0 ? "вентиляторы остановлены" : f <= 2300 ? "тихо — почти не слышно" : f <= 3500 ? "средне — слышно в тишине" : "громко";
}
function memLine(){
  const busy = ["mem_quick", "mem_full"].some(n => TASK[n]?.status === "running");
  const setup = TASK.memclean_set?.status === "running";
  const last = [TASK.mem_full, TASK.mem_quick].filter(t => t?.result).sort((a, b) => (b.finished || "").localeCompare(a.finished || ""))[0];
  const r = last?.result, err = TASK.mem_full?.error || TASK.mem_quick?.error || TASK.memclean_set?.error;
  const hint = "Windows и сама отдаёт эту память программам, когда нужно. Очистка помогает, если игра или программа подтормаживает из-за забитой памяти; сразу после неё программы могут на секунду медленнее открываться.";
  return `<div class="memline">
    <button class="small primary" data-memclean title="${esc(hint)}" ${busy ? "disabled" : ""}>${busy ? "Чищу память…" : "🧹 Очистить память"}</button>
    ${r ? `<span>Освобождено <b>${fmtB(r.freed)}</b> · занято ${Math.round(r.before.percent)}% → ${Math.round(r.after.percent)}%${r.mode === "quick" ? ` · сжато программ: ${r.processes}` : " · полная очистка"}</span>`
        : `<span>${M?.memclean_on ? "полная очистка — как в Mem Reduct" : "быстрая очистка: сжимает память программ"}</span>`}
    ${M && M.memclean_on === false ? `<a data-task-run="memclean_set" data-args='{"enable":true}'>${setup ? "жду подтверждения UAC…" : "включить полную очистку, как в Mem Reduct (один раз UAC)"}</a>` : ""}
    ${err ? `<span style="color:var(--bad)">${esc(err)}</span>` : ""}
  </div>`;
}
function heatLine(h){
  if (!h) return "";
  const c = h.culprits?.[0];
  if (h.now >= 70 || h.rise >= 10 || h.throttle) {
    const why = h.reasons.find(r => r[0] === "bad") || h.reasons.find(r => r[0] === "warn");
    return `<div class="load" style="color:var(--warn)">🌡 Видеокарта ${Math.round(h.now)}°C${c ? ` — греет <b style="color:var(--text)">${esc(c.name.replace(/\.exe$/i, ""))}</b> (${c.avg}% в среднем)` : ""}${why ? ". " + esc(why[1]) : ""}</div>`;
  }
  return c && c.avg >= 10 ? `<div class="load">Видеокарту нагружает: <b>${esc(c.name.replace(/\.exe$/i, ""))}</b> ${c.avg}%</div>` : "";
}
function cpuLine(c){
  if (!c || c.now < 50) return "";
  const top = c.culprits?.[0];
  return `<div class="load" style="color:var(--warn)">⚙ Процессор загружен на ${Math.round(c.now)}%${top ? ` — больше всего <b style="color:var(--text)">${esc(top.name.replace(/\.exe$/i, ""))}</b> (${Math.round(top.avg)}% в среднем${top.title ? ", " + esc(top.title.toLowerCase()) : ""})` : ""}</div>`;
}
function drawCpuWhy(){
  const box = $("#cpuBox"), c = M?.cpu_why;
  if (!box) return;
  box.hidden = !c;
  if (!c) return;
  const lvl = {bad: "var(--crit)", warn: "var(--warn)", info: "var(--info)", ok: "var(--accent)"};
  box.innerHTML = `<h4>Почему нагружен процессор</h4>
    <div class="legend" style="flex-wrap:wrap">
      <span>сейчас <b style="color:var(--text)">${Math.round(c.now)}%</b></span>
      <span>за ${Math.max(1, Math.round(c.window_s / 60))} мин: в среднем ${Math.round(c.avg)}%, пик ${Math.round(c.peak)}%</span>
      ${c.temp != null ? `<span>температура <b style="color:var(--text)">${Math.round(c.temp)}°C</b> (${Math.round(c.temp_min)}–${Math.round(c.temp_max)}°C)</span>` : ""}
      ${c.idle_s != null && c.idle_s >= 60 ? `<span>ты не трогал компьютер ${Math.floor(c.idle_s / 60)} мин</span>` : ""}</div>
    <div class="checks" style="margin-top:8px">${c.reasons.map(r => `<div class="check" style="grid-template-columns:14px 1fr"><span class="lvl" style="background:${lvl[r[0]]};margin-top:6px"></span><span>${esc(r[1])}</span></div>`).join("")}</div>
    <div class="grp" style="margin-top:10px">Кто грузил процессор за последние ${Math.max(1, Math.round(c.window_s / 60))} мин</div>
    <table class="t small procs">${c.culprits.length ? c.culprits.map(x => `<tr><td>${esc(x.name)}${x.count > 1 ? `<span class="sub"> ×${x.count}</span>` : ""}${x.title ? `<div class="sub">${esc(x.title)}</div>` : ""}</td>
      <td class="n">в среднем ${x.avg}%</td><td class="n sub">пик ${x.peak}%</td>
      <td class="acts">${x.exe ? `<a data-open="${esc(x.exe)}">папка</a>` : ""}${x.exe && !x.title ? `<a data-scan-exe="${esc(x.exe)}">проверить</a>` : ""}</td></tr>`).join("")
      : `<tr><td class="sub">никто заметно не нагружал</td></tr>`}</table>
    <div class="sub" style="margin-top:6px">Наведи на график процессора — в подсказке видно, какая программа грузила его в тот момент. Одинаковые процессы (вкладки браузера, службы) складываются.</div>`;
}
function drawHeat(){
  const box = $("#heatBox"), h = M?.heat;
  if (!box) return;
  box.hidden = !h;
  if (!h) return;
  const lvl = {bad: "var(--crit)", warn: "var(--warn)", info: "var(--info)", ok: "var(--accent)"};
  const procs = (M.gpu_procs || []).filter(p => p.util >= 0.5 || p.mem >= 200).slice(0, 6);
  box.innerHTML = `<h4>Почему греется видеокарта</h4>
    <div class="legend" style="flex-wrap:wrap">
      <span>сейчас <b style="color:var(--text)">${Math.round(h.now)}°C</b></span>
      <span>за 5 мин: ${Math.round(h.min)}–${Math.round(h.max)}°C${h.rise >= 1 ? ` (выросла на ${h.rise}°)` : ""}</span>
      ${h.tlimit != null ? `<span>до троттлинга: <b style="color:${h.tlimit <= 10 ? "var(--crit)" : "var(--text)"}">${Math.round(h.tlimit)}°C</b></span>` : ""}
      ${h.clock ? `<span>частота ${h.clock}/${h.clock_max} МГц · ${esc(h.pstate || "")}</span>` : ""}
      ${h.power != null ? `<span>${h.power} Вт</span>` : ""}</div>
    <div class="checks" style="margin-top:8px">${h.reasons.map(r => `<div class="check" style="grid-template-columns:14px 1fr"><span class="lvl" style="background:${lvl[r[0]]};margin-top:6px"></span><span>${esc(r[1])}</span></div>`).join("")}</div>
    <div class="charts" style="margin-top:10px">
      <div><div class="grp">Грузили видеокарту за последние ${Math.max(1, Math.round(h.window_s / 60))} мин</div>
        <table class="t small procs">${h.culprits.length ? h.culprits.map(c => `<tr><td>${esc(c.name)}${c.engine ? `<div class="sub">${esc(c.engine)}</div>` : ""}</td><td class="n">в среднем ${c.avg}%</td><td class="n sub">пик ${c.peak}%</td></tr>`).join("")
          : `<tr><td class="sub">никто заметно не нагружал</td></tr>`}</table></div>
      <div><div class="grp">Сейчас: нагрузка и видеопамять по программам</div>
        <table class="t small procs">${procs.map(p => `<tr><td>${esc(p.name)}${p.engine && p.util >= 1 ? `<div class="sub">${esc(p.engine)}</div>` : ""}</td><td class="n">${p.util}%</td><td class="n sub">${p.mem ? p.mem + " МБ" : ""}</td></tr>`).join("") || `<tr><td class="sub">нет данных</td></tr>`}</table></div>
    </div>
    <div class="sub" style="margin-top:6px">Наведи на график температуры — в подсказке будет видно, какая программа грузила видеокарту в тот момент. Учитываются и встроенная, и дискретная видеокарты.</div>`;
}
let metricsBusy = false;
async function pollMetrics(){
  const want = ["home", "res"].includes(PAGE) || (PAGE === "speed" && ["memory", "noise", "game"].includes(SUB)) || (PAGE === "health" && SUB === "hw");
  if (!want || metricsBusy || document.hidden) return;
  metricsBusy = true;
  try { M = await api("/api/metrics"); drawRes(); gpuLiveTick() } catch (e) { $("#sRes").innerHTML = `<div class="sub">${esc(e.message)}</div>` }
  metricsBusy = false;
}
setInterval(pollMetrics, 1500);
$("#procSort").onclick = e => {
  const b = e.target.closest("[data-sort]"); if (!b) return;
  procSort = b.dataset.sort;
  document.querySelectorAll("#procSort button").forEach(x => x.classList.toggle("on", x === b));
  drawRes();
};
document.addEventListener("click", async e => {
  const a = e.target.closest("[data-scan-exe],[data-open],[data-why],[data-kill]");
  if (!a) return;
  if (a.dataset.open) return api("/api/open", {path: a.dataset.open});
  if (a.dataset.why) { run("witr", "pid", a.dataset.why); return }
  if (a.dataset.kill) {
    if (!await ask(`Завершить ${a.dataset.name} (PID ${a.dataset.kill})? Несохранённые данные в этой программе пропадут.`)) return;
    try { await api("/api/kill", {pid: +a.dataset.kill}); toast(`${a.dataset.name} завершён`, `PID ${a.dataset.kill}`) }
    catch (err) { toast("Не получилось завершить процесс", err.message, "err") }
    return pollMetrics();
  }
  if (a.dataset.scanExe) {
    const tools = TOOLS.filter(t => t.ready && !t.data_missing && t.modes.some(m => m.multi));
    if (MODE === "simple") { go("scan", "check"); simpleBatch = await scanBatch(a.dataset.scanExe, tools, {kind: "file"}); renderSimpleResult(); window.scrollTo({top: 0, behavior: "smooth"}) }
    else { go("tools"); $("#target").value = a.dataset.scanExe; scanBatch(a.dataset.scanExe, tools); window.scrollTo({top: 0}) }
  }
});

