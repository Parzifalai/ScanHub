// ============================================================ Видеокарта вживую и FPS в играх
// Мощность видеокарты обновляется каждые 1,5 с (те же данные, что «Ресурсы»): видно, как растёт лимит, когда подключаешь зарядку.
// FPS: счётчик PresentMon (сервер: fps.py) + окошко поверх игры (overlay.py), итоги игр — здесь же.

const GPU_HIST = [];
function gpuLiveHtml(){
  const g = M?.gpu, bat = M?.now?.battery;
  if (!g || g.power == null) return M ? "" : `<div class="gpul"><div class="sub">Смотрю на видеокарту…</div></div>`;
  const lim = g.power_limit, max = g.power_max, w = g.power;
  const full = lim && max ? lim >= max * 0.95 : null;
  const plugged = bat ? bat.plugged : null;
  const verdict = !lim || !max ? ""
    : plugged === false ? `${sevChip(["warn", "От батареи"])} Видеокарта ограничена, пока ноутбук не на зарядке. Подключи зарядку — лимит поднимется сам.`
    : full ? `${sevChip(["ok", "Вся мощность"])} Видеокарте разрешено ${Math.round(lim)} Вт — это её максимум.`
    : `${sevChip(["info", "Не вся мощность"])} Зарядка подключена, но включён тихий или сбалансированный режим. Включи «Производительность» (на Lenovo — Fn+Q) — лимит поднимется до ${Math.round(max)} Вт.`;
  const bars = GPU_HIST.slice(-60).map(v => `<i style="height:${Math.max(3, Math.round(v / (max || 120) * 100))}%"></i>`).join("");
  return `<div class="gpul"><div class="gpul-h"><b>Видеокарта сейчас</b><span class="sub">${esc(g.name || "")}</span><div class="grow"></div>
      <span class="sub">${plugged == null ? "" : plugged ? "⚡ от зарядки" : "🔋 от батареи"}</span></div>
    <div class="gpul-row"><div class="gpul-big"><b>${Math.round(w)}</b> Вт<span class="sub">потребляет сейчас</span></div>
      ${lim && max ? `<div class="gpul-lim"><div class="gpul-bar"><div style="width:${Math.min(100, w / max * 100)}%"></div><span class="gpul-mark" style="left:${Math.min(100, lim / max * 100)}%" title="лимит сейчас"></span></div>
        <div class="sub">лимит сейчас <b style="color:var(--text)">${Math.round(lim)} Вт</b> из ${Math.round(max)} Вт возможных</div></div>` : ""}
      <div class="gpul-spark" title="мощность за последнюю минуту">${bars}</div></div>
    <div class="sub">${[g.util != null ? `нагрузка ${Math.round(g.util)}%` : "", g.temp != null ? `${Math.round(g.temp)}°C` : "", g.clock ? `${Math.round(g.clock)} МГц` : ""].filter(Boolean).join(" · ")}</div>
    ${verdict ? `<div class="gpul-v">${verdict}</div>` : ""}</div>`;
}
// после каждого опроса датчиков — обновить живые блоки, не перерисовывая весь раздел
function gpuLiveTick(){
  if (M?.gpu?.power != null) { GPU_HIST.push(M.gpu.power); if (GPU_HIST.length > 120) GPU_HIST.shift() }
  document.querySelectorAll("[data-gpu-live]").forEach(el => el.innerHTML = gpuLiveHtml());
}

// ---------- FPS
let FPS = null, FPS_T = 0;
async function fpsPoll(){
  if (!(PAGE === "speed" && SUB === "game") || document.hidden) return;
  try { const was = FPS?.on; FPS = await api("/api/fps"); if (was !== FPS.on || !document.getElementById("fpsLive")) redrawPanels(); else fpsLiveDraw() } catch {}
}
setInterval(fpsPoll, 1000);
function fpsLiveDraw(){
  const el = document.getElementById("fpsLive");
  if (!el || !FPS) return;
  el.innerHTML = !FPS.on ? "" : FPS.status === "uac" ? `<div class="sub">Подтверди окно UAC — без прав администратора Windows не показывает кадры.</div>`
    : FPS.fps == null ? `<div class="sub">Счётчик работает. Запусти игру — FPS появится в углу экрана и здесь.</div>`
    : `<div class="fps-now"><b style="color:${FPS.fps >= 55 ? "var(--ok)" : FPS.fps >= 30 ? "var(--warn)" : "var(--bad)"}">${FPS.fps}</b><span>FPS<span class="sub">${esc(FPS.app || "")}${FPS.low1 ? ` · просадки до ${FPS.low1}` : ""}</span></span></div>`;
}
const FPS_CORNERS = [["tl", "слева сверху"], ["tr", "справа сверху"], ["bl", "слева снизу"], ["br", "справа снизу"]];
function fpsBlock(){
  const f = FPS, on = f?.on, ses = f?.sessions || [];
  const verdictRow = s => { const v = s.verdict || ["info", ""];
    return `<tr><td><b>${esc(s.app.replace(/\.exe$/i, ""))}</b><div class="sub">${esc(ago(s.start))} · ${s.minutes} мин</div></td>
      <td><b>${s.avg}</b> <span class="sub">в среднем</span><div class="sub">просадки до ${s.low1}</div></td>
      <td>${sevChip([v[0], v[1]])}${v[2] ? `<div class="sub">${esc(v[2])}</div>` : ""}</td>
      <td class="sub">${s.gpu_temp_max ? `GPU до ${s.gpu_temp_max}°C` : ""}${s.gpu_w_avg ? ` · ${s.gpu_w_avg} Вт` : ""}${s.cpu_temp_max ? `<br>CPU до ${s.cpu_temp_max}°C` : ""}</td></tr>` };
  return `<div class="fpsb"><div class="fpsb-h"><b>FPS в играх</b>${on ? sevChip(["ok", "включено"]) : ""}<div class="grow"></div>
      ${on ? `<button class="danger" data-fps="stop">Выключить показ FPS</button>` : `<button class="primary" data-fps="start">Показывать FPS в игре</button>`}</div>
    <div class="sub">Маленькое окошко в углу экрана: FPS, просадки, температура и мощность видеокарты. Мышь проходит сквозь него, игре не мешает. После игры здесь появится итог: шла ли игра плавно и что мешало.
      Нужно одно окно UAC: без прав администратора Windows не показывает кадры. Окно ScanHub можно закрыть — счётчик доработает, пока не выключишь.</div>
    <div class="row" style="margin-top:8px;gap:6px;align-items:center"><span class="sub">Где показывать:</span>${FPS_CORNERS.map(([id, t]) => `<button class="small${(f?.corner || "tl") === id ? " primary" : ""}" data-fps-corner="${id}">${t}</button>`).join("")}</div>
    ${f?.error ? `<div class="note warn">${esc(f.error)}</div>` : ""}
    <div id="fpsLive"></div>
    <div class="sub" style="margin-top:6px">Не видно окошка в игре? Поставь в настройках игры режим экрана «Оконный без рамки» (Borderless) — в «Полноэкранном» Windows рисует игру поверх всего.</div>
    ${ses.length ? `<div class="grp" style="margin-top:12px">Последние игры</div><table class="t small">${ses.map(verdictRow).join("")}</table>` : ""}</div>`;
}
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-fps],[data-fps-corner]");
  if (!b) return;
  if (b.dataset.fpsCorner) { FPS = await api("/api/fps", {action: "corner", corner: b.dataset.fpsCorner}); return redrawPanels() }
  b.disabled = true; b.textContent = b.dataset.fps === "start" ? "Включаю… (подтверди UAC)" : "Выключаю…";
  try { FPS = await api("/api/fps", {action: b.dataset.fps, corner: FPS?.corner}) } catch (err) { toast("Не получилось", err.message, "warn") }
  if (b.dataset.fps === "stop" && FPS?.sessions?.length) toast("Итог игры готов", "смотри «Последние игры» в «Игровом режиме»");
  redrawPanels();
});
