// ============================================================ «Здоровье ПК → Устройства»
// Что подключено и работает ли (сервер: devices.py) + живые проверки прямо в окне: микрофон, динамики, клавиатура, мышь, камера.
// Живые проверки ничего не записывают и никуда не отправляют — звук и картинка остаются в окне и пропадают, как только проверку закрыть.

const DEV_ICON = {keyboard: "⌨", mouse: "🖱", mic: "🎙", speaker: "🔊", camera: "📷", bluetooth: "ᛒ", portable: "📱"};
const DEV_TEST = {keyboard: "kbd", mouse: "mouse", mic: "mic", speaker: "spk", camera: "cam"};
const DEV_SETTINGS = {keyboard: ["typing", "Параметры клавиатуры"], mouse: ["mouse", "Параметры мыши"], mic: ["sound", "Параметры звука"],
  speaker: ["sound", "Параметры звука"], camera: ["cam_privacy", "Доступ к камере"], bluetooth: ["bluetooth", "Bluetooth"]};
const DT = {cur: null, stream: null, ctx: null, raf: 0, timers: [], kbd: null, mouse: null, mic: null};

function devChip(lvl){ return sevChip(lvl === "bad" ? ["bad", "Не работает"] : lvl === "warn" ? ["warn", "Стоит посмотреть"] : ["ok", "Всё в порядке"]) }

function pDevices(dev){
  const t = TASK.devices, r = t?.result;
  const right = `<button data-task-run="devices" ${t?.status === "running" ? "disabled" : ""}>${r ? "Проверить снова" : "Проверить"}</button>`;
  const intro = explain("Что подключено к компьютеру и работает ли: клавиатура, мышь, микрофон, звук, камера, Bluetooth. Здесь же можно проверить каждое устройство вживую — понажимать клавиши, пощёлкать мышью, сказать что-нибудь в микрофон. Звук и картинка с камеры никуда не уходят и не записываются.");
  if (!r) return pnl(head("Устройства", "", right) + intro + busyErr("devices", "Смотрю, что подключено… пара секунд"));
  const sum = r.bad ? `<div class="note bad"><b>Не работает: ${r.groups.filter(g => g.lvl === "bad").map(g => g.title.toLowerCase()).join(", ")}.</b> Ниже — почему и что сделать.</div>`
    : r.warn ? `<div class="note warn"><b>Всё подключено, но есть что посмотреть:</b> ${r.groups.filter(g => g.lvl === "warn").map(g => g.title.toLowerCase()).join(", ")}.</div>`
    : `<div class="note ok-note"><b>Все устройства работают.</b> Если что-то всё равно ведёт себя странно — проверь его вживую кнопкой «Проверить».</div>`;
  const groups = r.groups.map(g => {
    const test = DEV_TEST[g.id], st = DEV_SETTINGS[g.id];
    const none = !g.items.length ? `<div class="sub">${g.id === "mic" ? "Микрофон не найден. Если он есть (в ноутбуке или наушниках) — проверь, что наушники вставлены до конца, и загляни в «Параметры звука»." : g.id === "speaker" ? "Устройств вывода звука нет — Windows не видит ни динамиков, ни наушников." : "Не найдено."}</div>` : "";
    return `<div class="devg" data-devg="${g.id}"><div class="devg-h"><span class="devg-ic" aria-hidden="true">${DEV_ICON[g.id] || "•"}</span><b>${esc(g.title)}</b>${devChip(g.lvl)}<div class="grow"></div>
        ${test ? `<button class="small${g.lvl !== "ok" ? " primary" : ""}" data-dtest="${test}">Проверить</button>` : ""}${st ? `<button class="small ghost" data-launch="${st[0]}">${esc(st[1])}</button>` : ""}</div>
      ${none}${g.items.map(d => `<div class="devi"><span class="dot dot-${d.state}"></span><span class="devi-n">${esc(d.name)}${d.n > 1 ? ` <span class="sub-inline">×${d.n}</span>` : ""}
          <span class="sub">${[d.link, d.kind, d.text].filter(Boolean).map(esc).join(" · ")}${d.battery != null ? ` · заряд ${d.battery}%` : ""}</span>
          ${d.hint ? `<span class="dev-hint">${esc(d.hint)}</span>` : ""}${dev ? `<span class="mono sub">${esc(d.id)}</span>` : ""}</span>
          ${d.state === "bad" ? `<span class="acts"><button class="small" data-launch="devmgmt">Диспетчер устройств</button>${aiBtn(d.name + ": " + d.text, d.hint || "", {source: "Здоровье ПК · Устройства"})}</span>` : ""}</div>`).join("")}
      ${g.issues.map(x => `<div class="devi"><span class="dot dot-${x.lvl === "bad" ? "bad" : x.lvl === "warn" ? "warn" : "info"}"></span><span class="devi-n">${esc(x.t)}<span class="sub">${esc(x.s)}</span></span>
          <span class="acts">${x.fix ? `<button class="small${x.lvl === "info" ? "" : " primary"}" data-dfix="${esc(x.fix)}">${x.lvl === "info" ? "Выключить" : "Исправить"}</button>` : ""}</span></div>`).join("")}
      <div class="dtest" id="dtest-${test || g.id}"></div></div>`;
  }).join("");
  const usedRow = (u, w) => u.map(x => `<tr><td><b>${esc(x.app)}</b>${x.now ? ` ${sevChip(["warn", "прямо сейчас"])}` : ""}<div class="sub mono">${esc(x.path)}</div></td><td class="sub">${esc(w)}</td><td class="sub">${esc(ago(new Date(x.start * 1000).toISOString()))}</td></tr>`).join("");
  const used = r.mic_used.length || r.cam_used.length ? `<details class="dsec"><summary class="grp">Кто пользовался микрофоном и камерой за 30 дней · ${r.mic_used.length + r.cam_used.length}</summary>
      <div class="sub" style="margin:2px 0 6px">Windows сама запоминает, какие программы включали микрофон и камеру. Если видишь незнакомую — проверь её на вирусы.</div>
      <table class="t small">${usedRow(r.mic_used, "микрофон")}${usedRow(r.cam_used, "камера")}</table></details>` : "";
  return pnl(`${head("Устройства", `проверено ${esc(ago(r.when))}`, right)}${intro}${busyErr("devices", "Проверяю…")}${busyErr("device_fix", "Исправляю…")}${sum}
    <div class="devgs">${groups}</div>${used}`) + (setTimeout(dtestRestore, 0), "");
}

// ---------- живые проверки
function dtestStop(){
  cancelAnimationFrame(DT.raf); DT.raf = 0;
  DT.timers.forEach(clearTimeout); DT.timers = [];
  DT.stream?.getTracks().forEach(t => t.stop()); DT.stream = null;
  try { DT.ctx?.close() } catch {}
  DT.ctx = null;
  if (DT.rec?.state === "recording") try { DT.rec.stop() } catch {}
  DT.rec = null;
  document.removeEventListener("keydown", kbdDown, true); document.removeEventListener("keyup", kbdUp, true);
  kbdUnlock();
  document.querySelectorAll(".dtest").forEach(el => { el.innerHTML = ""; el.classList.remove("on") });
  DT.cur = null; DT.el = null;
}
function dtestBox(kind){ return document.getElementById("dtest-" + kind) }
// раздел перерисовался (закончилась другая задача) — переносим идущую проверку в новую разметку, не перезапуская её
function dtestRestore(){
  const box = DT.cur && dtestBox(DT.cur);
  if (box && DT.el && !box.contains(DT.el)) { box.appendChild(DT.el); box.classList.add("on") }
}
function dtestOpen(kind){
  if (DT.cur === kind) return dtestStop();
  dtestStop();
  DT.cur = kind;
  const box = dtestBox(kind);
  if (!box) return;
  box.classList.add("on");
  DT.el = document.createElement("div");
  box.appendChild(DT.el);
  ({mic: micTest, spk: spkTest, kbd: kbdTest, mouse: mouseTest, cam: camTest})[kind]?.(DT.el);
}
const dclose = `<button class="small ghost" data-dtest-stop>Закончить проверку</button>`;
const mediaErr = (e, what) => /NotAllowed|Permission/i.test(e?.name || e?.message || "")
  ? `Окно ScanHub не получило доступ к ${what}. Разреши его во всплывающем вопросе вверху окна или включи доступ в «Параметры → Конфиденциальность». ${what === "микрофону" ? '<button class="small" data-launch="mic_privacy">Открыть</button>' : '<button class="small" data-launch="cam_privacy">Открыть</button>'}`
  : /NotFound|DevicesNotFound/i.test(e?.name || "") ? `Windows не нашла ${what === "микрофону" ? "ни одного микрофона" : "ни одной камеры"}.`
  : /NotReadable|TrackStart/i.test(e?.name || "") ? `${what === "микрофону" ? "Микрофон" : "Камера"} сейчас занят другой программой (Discord, Zoom, Telegram…) или выключен кнопкой на корпусе. Закрой ту программу и попробуй снова.`
  : `Не получилось включить: ${esc(e?.message || e)}`;

// микрофон: уровень в реальном времени, вердикт по пику, запись 3 с и прослушивание
async function micTest(box, deviceId){
  box.innerHTML = `<div class="dt-h"><b>Проверка микрофона</b><div class="grow"></div>${dclose}</div><div class="sub">Скажи что-нибудь обычным голосом — полоса должна прыгать.</div><div class="sub" id="micState">Включаю микрофон…</div>`;
  try {
    DT.stream = await navigator.mediaDevices.getUserMedia({audio: deviceId ? {deviceId: {exact: deviceId}} : true});
  } catch (e) { box.querySelector("#micState").innerHTML = mediaErr(e, "микрофону"); return }
  const devs = (await navigator.mediaDevices.enumerateDevices()).filter(d => d.kind === "audioinput" && d.deviceId !== "communications");
  const curId = DT.stream.getAudioTracks()[0]?.getSettings().deviceId;
  box.innerHTML = `<div class="dt-h"><b>Проверка микрофона</b><div class="grow"></div>${devs.length > 1 ? `<select id="micSel">${devs.map(d => `<option value="${esc(d.deviceId)}" ${d.deviceId === curId ? "selected" : ""}>${esc(d.label || "Микрофон")}</option>`).join("")}</select>` : ""}${dclose}</div>
    <div class="sub">Скажи что-нибудь обычным голосом — полоса должна прыгать.</div>
    <div class="meter"><div id="micBar"></div><span id="micPeak"></span></div>
    <div id="micVerdict" class="sub">Слушаю…</div>
    <div class="row" style="margin-top:8px"><button class="small" data-mic-rec>Записать 3 секунды и послушать</button><span class="sub" id="micRecSt"></span></div>`;
  box.querySelector("#micSel")?.addEventListener("change", e => { const id = e.target.value; dtestStop(); DT.cur = "mic"; const b = dtestBox("mic"); b.classList.add("on"); DT.el = document.createElement("div"); b.appendChild(DT.el); micTest(DT.el, id) });
  DT.ctx = new AudioContext();
  const src = DT.ctx.createMediaStreamSource(DT.stream), an = DT.ctx.createAnalyser();
  an.fftSize = 2048; src.connect(an);
  const buf = new Float32Array(an.fftSize);
  let peak = -100, loud = 0, clip = 0, frames = 0;
  const t0 = performance.now();
  const tick = () => {
    an.getFloatTimeDomainData(buf);
    let sum = 0, mx = 0;
    for (const v of buf) { sum += v * v; mx = Math.max(mx, Math.abs(v)) }
    const db = 20 * Math.log10(Math.sqrt(sum / buf.length) || 1e-6);
    peak = Math.max(peak, db); frames++;
    if (db > -45) loud++;
    if (mx > 0.98) clip++;
    const bar = document.getElementById("micBar");
    if (!bar) { if (DT.cur === "mic") DT.raf = requestAnimationFrame(tick); return }
    bar.style.width = Math.max(0, Math.min(100, (db + 70) / 70 * 100)) + "%";
    bar.className = db > -6 ? "hot" : db > -45 ? "good" : "";
    document.getElementById("micPeak").textContent = `${Math.round(db)} дБ`;
    const sec = (performance.now() - t0) / 1000;
    const v = document.getElementById("micVerdict");
    if (sec > 2.5) v.innerHTML = peak < -75 ? `${sevChip(["bad", "Тишина"])} Звук не приходит совсем. Проверь, не выключен ли микрофон кнопкой или шторкой на корпусе, выбран ли нужный микрофон в списке и не стоит ли громкость микрофона на нуле в «Параметрах звука». <button class="small" data-launch="sound">Параметры звука</button>`
      : peak < -50 ? `${sevChip(["warn", "Очень тихо"])} Звук есть, но слабый. Говори ближе или прибавь громкость микрофона в «Параметрах звука» → микрофон → «Громкость».`
      : clip > Math.max(8, loud * 0.25) ? `${sevChip(["warn", "Перегружен"])} Звук «хрипит» на громких местах — убавь громкость микрофона.`
      : loud ? `${sevChip(["ok", "Работает"])} Микрофон слышит тебя нормально. Чтобы услышать, как ты звучишь, — запиши 3 секунды.`
      : `${sevChip(["info", "Слушаю"])} Скажи что-нибудь…`;
    DT.raf = requestAnimationFrame(tick);
  };
  tick();
}
async function micRecord(){
  if (!DT.stream || DT.rec) return;
  const st = document.getElementById("micRecSt");
  const chunks = [];
  DT.rec = new MediaRecorder(DT.stream);
  DT.rec.ondataavailable = e => { if (e.data?.size) chunks.push(e.data) };
  DT.rec.onstop = async () => {
    DT.rec = null;
    if (!chunks.length) { if (st) st.textContent = "Запись пустая — микрофон ничего не передал."; return }
    // проигрываем через звук страницы с усилением: тихий микрофон иначе почти не слышно в динамиках
    try {
      const ctx = DT.ctx && DT.ctx.state !== "closed" ? DT.ctx : (DT.ctx = new AudioContext());
      await ctx.resume();
      const audio = await ctx.decodeAudioData(await new Blob(chunks, {type: chunks[0].type}).arrayBuffer());
      let pk = 0;
      for (let c = 0; c < audio.numberOfChannels; c++) for (const v of audio.getChannelData(c)) pk = Math.max(pk, Math.abs(v));
      DT.recBuf = audio; DT.recGain = pk > 0.001 ? Math.min(20, 0.8 / pk) : 1;
      micPlay();
    } catch (e) { if (st) st.textContent = "Не получилось воспроизвести запись: " + (e.message || e) }
  };
  DT.rec.start();
  let n = 3;
  if (st) st.textContent = "● запись: 3…";
  const step = () => { n--; if (n > 0) { if (st) st.textContent = `● запись: ${n}…`; DT.timers.push(setTimeout(step, 1000)) } else DT.rec?.stop() };
  DT.timers.push(setTimeout(step, 1000));
}
function micPlay(){
  const st = document.getElementById("micRecSt"), ctx = DT.ctx, buf = DT.recBuf;
  if (!ctx || !buf) return;
  const src = ctx.createBufferSource(), g = ctx.createGain();
  src.buffer = buf; g.gain.value = DT.recGain || 1;
  src.connect(g).connect(ctx.destination);
  src.onended = () => { if (st) st.innerHTML = `Готово${DT.recGain > 1.5 ? ` (запись была тихой — ScanHub усилил её в ${DT.recGain.toFixed(1)} раза, чтобы было слышно)` : ""}. Запись нигде не сохранилась. <button class="small" data-mic-play>▶ Послушать ещё раз</button>
    <div class="sub">Ничего не слышно? Проверь, куда выводится звук (динамики или наушники) и громкость. <button class="small ghost" data-launch="sound">Параметры звука</button></div>` };
  if (st) st.textContent = `▶ играет запись (${buf.duration.toFixed(1)} с)…`;
  src.start();
}

// динамики: тон слева, справа, по очереди
function spkTest(box){
  box.innerHTML = `<div class="dt-h"><b>Проверка звука</b><div class="grow"></div>${dclose}</div>
    <div class="sub">Сделай громкость потише — прозвучит короткий сигнал. Должно быть слышно с той стороны, которую нажал.</div>
    <div class="row" style="margin-top:8px"><button class="small" data-spk="-1">◀ Слева</button><button class="small" data-spk="0">Оба</button><button class="small" data-spk="1">Справа ▶</button><button class="small" data-spk="sweep">Низкие → высокие</button></div>
    <div class="sub" id="spkSt" style="margin-top:6px">Не слышно совсем — проверь, какое устройство выбрано для вывода звука. <button class="small ghost" data-launch="sound">Параметры звука</button></div>`;
}
function spkPlay(pan){
  DT.ctx = DT.ctx && DT.ctx.state !== "closed" ? DT.ctx : new AudioContext();
  const c = DT.ctx, o = c.createOscillator(), g = c.createGain(), p = c.createStereoPanner();
  const t = c.currentTime, len = pan === "sweep" ? 3 : 0.9;
  o.type = "sine";
  if (pan === "sweep") { o.frequency.setValueAtTime(60, t); o.frequency.exponentialRampToValueAtTime(12000, t + len) } else o.frequency.value = 660;
  p.pan.value = pan === "sweep" ? 0 : +pan;
  g.gain.setValueAtTime(0, t); g.gain.linearRampToValueAtTime(0.18, t + 0.05); g.gain.setValueAtTime(0.18, t + len - 0.1); g.gain.linearRampToValueAtTime(0, t + len);
  o.connect(g).connect(p).connect(c.destination);
  o.start(t); o.stop(t + len);
  const s = document.getElementById("spkSt");
  if (s) s.innerHTML = pan === "sweep" ? "Низкий гул должен плавно перейти в писк. Если на каком-то месте дребезжит — динамик повреждён или громкость слишком большая."
    : `Звучит ${pan === "-1" ? "слева" : pan === "1" ? "справа" : "с обеих сторон"}. Если слышно не с той стороны — наушники надеты наоборот или перепутаны каналы.`;
}

// клавиатура: какие клавиши нажимались, «дребезг» (одна клавиша печатает дважды) и залипание
const KBD_ROWS = [
  ["Escape", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12", "Delete"],
  ["Backquote", "Digit1", "Digit2", "Digit3", "Digit4", "Digit5", "Digit6", "Digit7", "Digit8", "Digit9", "Digit0", "Minus", "Equal", "Backspace"],
  ["Tab", "KeyQ", "KeyW", "KeyE", "KeyR", "KeyT", "KeyY", "KeyU", "KeyI", "KeyO", "KeyP", "BracketLeft", "BracketRight", "Backslash"],
  ["CapsLock", "KeyA", "KeyS", "KeyD", "KeyF", "KeyG", "KeyH", "KeyJ", "KeyK", "KeyL", "Semicolon", "Quote", "Enter"],
  ["ShiftLeft", "KeyZ", "KeyX", "KeyC", "KeyV", "KeyB", "KeyN", "KeyM", "Comma", "Period", "Slash", "ShiftRight", "ArrowUp"],
  ["ControlLeft", "MetaLeft", "AltLeft", "Space", "AltRight", "ControlRight", "ArrowLeft", "ArrowDown", "ArrowRight"],
];
const KBD_LBL = {Escape: "Esc", Backquote: "`", Minus: "-", Equal: "=", Backspace: "⌫", BracketLeft: "[", BracketRight: "]", Backslash: "\\", CapsLock: "Caps",
  Semicolon: ";", Quote: "'", Enter: "Enter", ShiftLeft: "Shift", ShiftRight: "Shift", Comma: ",", Period: ".", Slash: "/", ControlLeft: "Ctrl", ControlRight: "Ctrl",
  MetaLeft: "Win", AltLeft: "Alt", AltRight: "Alt", Space: "Пробел", ArrowUp: "↑", ArrowDown: "↓", ArrowLeft: "←", ArrowRight: "→", Delete: "Del", Tab: "Tab"};
const kLbl = c => KBD_LBL[c] || c.replace(/^Key|^Digit/, "");
function kbdTest(box){
  DT.kbd = {seen: new Set(), down: {}, up: {}, chatter: {}, n: 0};
  box.innerHTML = `<div class="dt-h"><b>Проверка клавиатуры</b><div class="grow"></div>${dclose}</div>
    <div class="sub">Нажимай клавиши по очереди — нажатые подсветятся. Те, что не загораются, не работают. На время проверки окно разворачивается на весь экран и клавиши ничего не делают — ни в ScanHub, ни в Windows (Win, Alt+Tab, Alt+F4 и другие).</div>
    <div class="sub" id="kbdLock"></div>
    <div class="kbd">${KBD_ROWS.map(r => `<div class="kr">${r.map(c => `<span class="kk k-${c}${c === "Space" ? " wide" : /Shift|Enter|Backspace|Caps|Tab|Control/.test(c) ? " mid" : ""}" data-k="${c}">${esc(kLbl(c))}</span>`).join("")}</div>`).join("")}</div>
    <div class="sub" id="kbdSt">Нажато клавиш: 0</div>`;
  document.addEventListener("keydown", kbdDown, true); document.addEventListener("keyup", kbdUp, true);
  kbdLock(box);
}
// полноэкранный режим + Keyboard Lock: тогда браузер сам забирает системные клавиши (Win, Alt+Tab, Alt+F4…), и Windows на них не реагирует.
// Ctrl+Alt+Del и Fn перехватить нельзя никому. Выйти: «Закончить проверку», Shift+Esc или удерживать Esc.
async function kbdLock(box){
  const note = t => { const el = document.getElementById("kbdLock"); if (el) el.innerHTML = t };
  try {
    if (!document.fullscreenElement) await Promise.race([box.requestFullscreen({navigationUI: "hide"}),
      new Promise((_, no) => setTimeout(() => no(new Error("окно не развернулось")), 3000))]);
    box.classList.add("kbd-fs");
    if (navigator.keyboard?.lock) { await navigator.keyboard.lock(); DT.kbdLocked = true }
    note(`${sevChip(["ok", "Системные клавиши отключены"])} Выйти — кнопка «Закончить проверку», Shift+Esc или удерживай Esc 2 секунды.`);
  } catch (e) {
    note(`${sevChip(["info", "Без блокировки"])} Не получилось развернуть окно — Win и Alt+Tab сработают как обычно.`);
  }
}
function kbdUnlock(){
  try { navigator.keyboard?.unlock() } catch {}
  DT.kbdLocked = false;
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  document.querySelectorAll(".kbd-fs").forEach(el => el.classList.remove("kbd-fs"));
}
document.addEventListener("fullscreenchange", () => { if (!document.fullscreenElement && DT.kbdLocked) { kbdUnlock(); const el = document.getElementById("kbdLock"); if (el) el.innerHTML = `${sevChip(["info", "Блокировка снята"])} Окно вышло из полного экрана — системные клавиши снова работают.` } });
function kbdDown(e){
  const K = DT.kbd;
  if (!K || e.code === "") return;
  if (e.code === "Escape" && e.shiftKey) { e.preventDefault(); return dtestStop() }
  e.preventDefault(); e.stopPropagation();
  const now = performance.now();
  if (!e.repeat && K.up[e.code] && now - K.up[e.code] < 35) K.chatter[e.code] = (K.chatter[e.code] || 0) + 1;     // отпустил и «нажалось» снова за 35 мс — так пальцем не успеть
  if (!e.repeat) { K.down[e.code] = now; K.n++ }
  K.seen.add(e.code);
  document.querySelectorAll(`.kk[data-k="${e.code}"]`).forEach(el => el.classList.add("on", "now"));
  kbdState();
}
function kbdUp(e){
  const K = DT.kbd;
  if (!K) return;
  e.preventDefault(); e.stopPropagation();
  K.up[e.code] = performance.now(); delete K.down[e.code];
  document.querySelectorAll(`.kk[data-k="${e.code}"]`).forEach(el => el.classList.remove("now"));
  kbdState();
}
function kbdState(){
  const K = DT.kbd, st = document.getElementById("kbdSt");
  if (!K || !st) return;
  const ch = Object.keys(K.chatter);
  const all = KBD_ROWS.flat(), left = all.filter(c => !K.seen.has(c));
  ch.forEach(c => document.querySelectorAll(`.kk[data-k="${c}"]`).forEach(el => el.classList.add("bad")));
  st.innerHTML = `Нажато разных клавиш: ${K.seen.size}${left.length && K.seen.size > 10 ? ` · ещё не нажимал: ${left.length}` : ""}`
    + (ch.length ? `<div style="margin-top:4px">${sevChip(["warn", "Дребезг"])} ${ch.map(kLbl).map(esc).join(", ")} — ${ch.length === 1 ? "клавиша сама «нажимается» дважды" : "клавиши сами «нажимаются» дважды"}. Так бывает, когда под клавишу попала пыль или крошки, или контакт изнашивается. Продуй клавишу; если не помогло — нужен ремонт.</div>` : "")
    + (K.seen.size >= all.length - 3 && !ch.length ? `<div style="margin-top:4px">${sevChip(["ok", "Работает"])} Все клавиши откликаются.</div>` : "")
    + `<div class="sub" style="margin-top:4px">Клавиши Fn и подсветки Windows не видит — их здесь не проверить. Выйти из проверки — кнопка выше или Shift+Esc.</div>`;
}

// мышь: кнопки, двойной щелчок сам по себе, колесо, частота опроса
function mouseTest(box){
  DT.mouse = {btn: {}, chatter: {}, last: {}, wheel: [0, 0], moves: [], hz: 0};
  box.innerHTML = `<div class="dt-h"><b>Проверка мыши</b><div class="grow"></div>${dclose}</div>
    <div class="sub">Пощёлкай всеми кнопками и покрути колесо в рамке ниже, затем быстро поводи мышью по рамке.</div>
    <div class="mzone" id="mZone" tabindex="0"><div class="mbtns">${["Левая", "Средняя (колесо)", "Правая", "Назад (боковая)", "Вперёд (боковая)"].map((n, i) => `<span class="mb" data-mb="${i}">${n}<b>0</b></span>`).join("")}</div>
      <div class="sub" id="mInfo">Колесо: вверх 0 · вниз 0 · частота опроса: подвигай мышью</div></div>
    <div class="sub" id="mSt"></div>`;
  const z = box.querySelector("#mZone");
  z.addEventListener("contextmenu", e => e.preventDefault());
  z.addEventListener("mousedown", e => {
    e.preventDefault();
    const M = DT.mouse, now = performance.now(), b = e.button;
    if (M.last[b] && now - M.last[b] < 80) M.chatter[b] = (M.chatter[b] || 0) + 1;    // два нажатия за 80 мс — так быстро пальцем не щёлкнуть
    M.last[b] = now; M.btn[b] = (M.btn[b] || 0) + 1;
    const el = z.querySelector(`[data-mb="${b}"]`);
    if (el) { el.classList.add("on"); el.querySelector("b").textContent = M.btn[b] }
    mouseState();
  });
  z.addEventListener("auxclick", e => e.preventDefault());
  z.addEventListener("wheel", e => { e.preventDefault(); DT.mouse.wheel[e.deltaY < 0 ? 0 : 1]++; mouseState() }, {passive: false});
  const ev = "onpointerrawupdate" in window ? "pointerrawupdate" : "pointermove";
  z.addEventListener(ev, e => {
    const M = DT.mouse, now = performance.now();
    const n = e.getCoalescedEvents ? Math.max(1, e.getCoalescedEvents().length) : 1;
    for (let i = 0; i < n; i++) M.moves.push(now);
    while (M.moves.length && now - M.moves[0] > 500) M.moves.shift();
    if (M.moves.length > 40) M.hz = Math.max(M.hz, Math.round(M.moves.length * 2));
    mouseState();
  });
}
function mouseState(){
  const M = DT.mouse, i = document.getElementById("mInfo"), st = document.getElementById("mSt");
  if (!M || !i) return;
  const hz = M.hz, hzTxt = !hz ? "подвигай мышью" : hz >= 700 ? `~${hz >= 900 ? 1000 : hz} Гц (игровая)` : hz >= 300 ? `~${hz} Гц` : `~${hz} Гц`;
  i.textContent = `Колесо: вверх ${M.wheel[0]} · вниз ${M.wheel[1]} · частота опроса: ${hzTxt}`;
  const ch = Object.keys(M.chatter).map(b => ["левая", "средняя", "правая", "боковая «назад»", "боковая «вперёд»"][b]);
  const pressed = Object.keys(M.btn).length;
  st.innerHTML = (ch.length ? `${sevChip(["warn", "Двойной щелчок сам по себе"])} Кнопка ${ch.join(", ")} иногда срабатывает дважды от одного нажатия. Это износ микропереключателя — известная болезнь мышей: помогает замена переключателя или гарантия. Ещё раз пощёлкай медленно, чтобы убедиться.`
    : pressed >= 3 ? `${sevChip(["ok", "Кнопки работают"])} Лишних двойных щелчков нет.` : "")
    + (hz && hz < 120 ? `<div style="margin-top:4px">${sevChip(["info", "Низкая частота"])} ~${hz} Гц — для работы хватает, для игр мало. У игровых мышей частота меняется в их программе (обычно 1000 Гц).</div>` : "");
}

// камера: картинка и её размер
async function camTest(box){
  box.innerHTML = `<div class="dt-h"><b>Проверка камеры</b><div class="grow"></div>${dclose}</div><div class="sub" id="camSt">Включаю камеру…</div>`;
  try { DT.stream = await navigator.mediaDevices.getUserMedia({video: {width: {ideal: 1920}, height: {ideal: 1080}}}) }
  catch (e) { box.querySelector("#camSt").innerHTML = mediaErr(e, "камере"); return }
  const s = DT.stream.getVideoTracks()[0]?.getSettings() || {};
  box.innerHTML = `<div class="dt-h"><b>Проверка камеры</b><div class="grow"></div>${dclose}</div>
    <video id="camV" autoplay muted playsinline class="camv"></video>
    <div class="sub">${sevChip(["ok", "Работает"])} ${s.width ? `${s.width}×${s.height}` : ""}${s.frameRate ? `, ${Math.round(s.frameRate)} кадров/с` : ""}. Чёрная картинка при этом — закрыта шторка на камере или выключена клавишей (на ноутбуках Lenovo это F8 или переключатель сбоку). Картинка никуда не записывается.</div>`;
  box.querySelector("#camV").srcObject = DT.stream;
}

document.addEventListener("click", async e => {
  const t = e.target.closest("[data-dtest],[data-dtest-stop],[data-mic-rec],[data-mic-play],[data-spk],[data-dfix]");
  if (!t) return;
  if (t.dataset.dtest) return dtestOpen(t.dataset.dtest);
  if (t.hasAttribute("data-dtest-stop")) return dtestStop();
  if (t.hasAttribute("data-mic-rec")) return micRecord();
  if (t.hasAttribute("data-mic-play")) return micPlay();
  if (t.dataset.spk) return spkPlay(t.dataset.spk);
  if (t.dataset.dfix) { await runTask("device_fix", {kind: t.dataset.dfix}); runTask("devices") }
});
// ушёл из раздела — микрофон и камера выключаются сразу
document.addEventListener("click", e => { if (DT.cur && e.target.closest("[data-go],[data-tab-go],[data-go-page],#side a")) dtestStop() }, true);
