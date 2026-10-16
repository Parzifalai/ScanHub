// Посредник ScanHub:
//   POST /report — «Нашёл ошибку?» / «Предложить улучшение»: принимает сообщение и пересылает автору в Telegram.
//   POST /ping   — анонимная отметка «ScanHub запущен сегодня» (только у тех, кто согласился): случайный номер копии, версия, язык.
//   GET  /stats?key=…  — страница для автора: сколько копий запускалось сегодня, за неделю, за месяц, всего; версии и языки.
// Ключ бота хранится только здесь (секрет BOT_TOKEN в настройках Worker), в открытом коде ScanHub его нет.
//
// Настройки Worker (Settings → Variables and Secrets / Bindings):
//   BOT_TOKEN — секрет: ключ бота от @BotFather
//   CHAT_ID   — кому пересылать: числовой ID автора в Telegram
//   USAGE     — привязка KV namespace (Bindings → KV namespace) для счётчика запусков
//   STATS_KEY — секрет: пароль для страницы /stats
//   (по желанию) Triggers → Cron «0 18 * * *» — раз в день присылать сводку в Telegram
//
// Защита от спама: не больше 5 отчётов за 10 минут с одного адреса и 200 за сутки всего, отчёт до 24 КБ.

const PER_IP = 5, PER_IP_WINDOW = 600, PER_DAY = 200, MAX_BYTES = 24 * 1024, MAX_WITH_PHOTOS = 2600 * 1024, MAX_PHOTOS = 3;

const json = (body, status = 200) => new Response(JSON.stringify(body), {status, headers: {"Content-Type": "application/json; charset=utf-8"}});
const html = s => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const cut = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + "…" : s };

// счётчик в кэше Cloudflare: приблизительный (на каждый дата-центр свой), но от спама хватает и ничего не стоит
async function bump(key, ttl){
  const cache = caches.default, req = new Request("https://limits.scanhub/" + encodeURIComponent(key));
  const hit = await cache.match(req);
  const n = (hit ? parseInt(await hit.text(), 10) || 0 : 0) + 1;
  await cache.put(req, new Response(String(n), {headers: {"Cache-Control": `max-age=${ttl}`}}));
  return n;
}

async function tg(env, method, body){
  const init = {method: "POST", body};
  if (typeof body === "string") init.headers = {"Content-Type": "application/json"};
  const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, init);
  const j = await r.json().catch(() => ({}));
  if (!j.ok) throw new Error(j.description || `Telegram ответил ${r.status}`);
  return j;
}

// ---------- счётчик запусков: одна запись KV на копию, всё нужное — в метаданных (их отдаёт list без отдельных чтений)
const DAY = 86400000;
async function ping(req, env){
  if (!env.USAGE) return json({ok: false, error: "счётчик не настроен"}, 503);
  let r;
  try { r = JSON.parse((await req.text()).slice(0, 2000)) } catch { return json({ok: false}, 400) }
  if (r?.app !== "scanhub" || !/^[0-9a-f]{32}$/.test(r.id || "")) return json({ok: false}, 400);
  const ip = req.headers.get("CF-Connecting-IP") || "unknown";
  if (await bump("ping:" + ip, 3600) > 30) return json({ok: false}, 429);
  const key = "u:" + r.id, today = new Date().toISOString().slice(0, 10);
  const old = (await env.USAGE.getWithMetadata(key)).metadata;
  if (old?.last === today) return json({ok: true});
  const meta = {first: old?.first || today, last: today, v: cut(r.v, 16), lang: cut(r.lang, 5), win: cut(r.win, 8), days: (old?.days || 0) + 1};
  await env.USAGE.put(key, "", {metadata: meta});
  return json({ok: true});
}
async function usageAll(env){
  const out = [];
  let cursor;
  do {
    const page = await env.USAGE.list({prefix: "u:", cursor});
    for (const k of page.keys) if (k.metadata) out.push(k.metadata);
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  return out;
}
function summary(all){
  const now = Date.now(), ago = d => Math.floor((now - Date.parse(d + "T12:00:00Z")) / DAY);
  const n = days => all.filter(u => ago(u.last) < days).length;
  const by = (f, days = 30) => Object.entries(all.filter(u => ago(u.last) < days).reduce((m, u) => (m[f(u)] = (m[f(u)] || 0) + 1, m), {})).sort((a, b) => b[1] - a[1]);
  const fresh = all.filter(u => ago(u.first) < 7).length;
  const perDay = [...Array(30)].map((_, i) => { const d = new Date(now - (29 - i) * DAY).toISOString().slice(0, 10);
    return [d, all.filter(u => u.first === d).length, all.filter(u => u.last >= d && u.first <= d).length] });
  return {today: n(1), week: n(7), month: n(30), total: all.length, fresh, loyal: all.filter(u => u.days >= 5).length,
          versions: by(u => u.v || "?"), langs: by(u => u.lang || "?"), win: by(u => +u.win >= 22000 ? "Windows 11" : u.win ? "Windows 10" : "?"), perDay};
}
async function stats(url, env){
  if (!env.USAGE || !env.STATS_KEY) return new Response("Счётчик не настроен: нужны привязка KV «USAGE» и секрет STATS_KEY.", {status: 503});
  if (url.searchParams.get("key") !== env.STATS_KEY) return new Response("Нет доступа", {status: 403});
  const s = summary(await usageAll(env));
  if (url.searchParams.get("format") === "json") return json(s);
  const tbl = rows => rows.map(([k, v]) => `<tr><td>${html(k)}</td><td>${v}</td></tr>`).join("");
  const max = Math.max(1, ...s.perDay.map(x => x[2]));
  return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ScanHub — статистика</title>
<style>body{font:15px system-ui,Segoe UI,sans-serif;margin:0;padding:20px;background:#0f1115;color:#e7e9ee}h1{font-size:20px;margin:0 0 14px}
.k{display:flex;gap:10px;flex-wrap:wrap}.k div{background:#1a1d24;border-radius:12px;padding:12px 16px;min-width:120px}.k b{display:block;font-size:26px}
.k span{color:#9aa3b2;font-size:13px}table{border-collapse:collapse;margin:8px 0 16px}td{padding:3px 14px 3px 0}h2{font-size:15px;margin:18px 0 4px;color:#9aa3b2}
.bars{display:flex;align-items:flex-end;gap:3px;height:90px}.bars div{flex:1;background:#3b82f6;border-radius:3px 3px 0 0;min-height:2px}.sub{color:#9aa3b2;font-size:12px}</style>
<h1>ScanHub — кто пользуется</h1>
<div class="k"><div><b>${s.today}</b><span>сегодня</span></div><div><b>${s.week}</b><span>за 7 дней</span></div><div><b>${s.month}</b><span>за 30 дней</span></div>
<div><b>${s.total}</b><span>копий всего</span></div><div><b>${s.fresh}</b><span>новых за неделю</span></div><div><b>${s.loyal}</b><span>запускали 5+ дней</span></div></div>
<h2>Активные копии по дням (30 дней)</h2><div class="bars">${s.perDay.map(x => `<div title="${x[0]}: активных ${x[2]}, новых ${x[1]}" style="height:${x[2] / max * 100}%"></div>`).join("")}</div>
<h2>Версии (активные за 30 дней)</h2><table>${tbl(s.versions)}</table><h2>Язык окна</h2><table>${tbl(s.langs)}</table><h2>Windows</h2><table>${tbl(s.win)}</table>
<p class="sub">Считаются только копии, владельцы которых согласились на анонимную статистику. Каждая копия — случайный номер; IP-адреса не хранятся.</p>`,
    {headers: {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}});
}

export default {
  // раз в день (если в Triggers настроен Cron) — короткая сводка автору в Telegram
  async scheduled(event, env){
    if (!env.USAGE || !env.BOT_TOKEN || !env.CHAT_ID) return;
    const s = summary(await usageAll(env));
    await tg(env, "sendMessage", JSON.stringify({chat_id: env.CHAT_ID,
      text: `📊 ScanHub: сегодня ${s.today}, за неделю ${s.week}, за месяц ${s.month}, всего копий ${s.total} (новых за неделю: ${s.fresh}).`})).catch(() => {});
  },
  async fetch(req, env){
    const url = new URL(req.url);
    if (req.method === "GET" && url.pathname === "/stats") return stats(url, env);
    if (req.method === "POST" && url.pathname === "/ping") return ping(req, env);
    if (req.method === "GET") return new Response("ScanHub: приём отчётов об ошибках работает", {headers: {"Content-Type": "text/plain; charset=utf-8"}});
    if (req.method !== "POST" || url.pathname !== "/report") return json({ok: false, error: "не найдено"}, 404);
    if (!env.BOT_TOKEN || !env.CHAT_ID) return json({ok: false, error: "посредник не настроен"}, 500);

    const len = Number(req.headers.get("Content-Length") || 0);
    if (len > MAX_WITH_PHOTOS) return json({ok: false, error: "отчёт слишком большой"}, 413);
    const raw = await req.text();
    if (raw.length > MAX_WITH_PHOTOS) return json({ok: false, error: "отчёт слишком большой"}, 413);
    let r;
    try { r = JSON.parse(raw) } catch { return json({ok: false, error: "неверный отчёт"}, 400) }
    if (r?.app !== "scanhub" || typeof r.text !== "string" || r.text.trim().length < 5) return json({ok: false, error: "пустой отчёт"}, 400);
    // снимки экрана: только JPEG/PNG, до трёх; без снимков отчёт по-прежнему не больше 24 КБ
    const photos = (Array.isArray(r.photos) ? r.photos : []).slice(0, MAX_PHOTOS).map(b64 => {
      try { const bin = Uint8Array.from(atob(String(b64)), c => c.charCodeAt(0));
        const jpg = bin[0] === 0xff && bin[1] === 0xd8, png = bin[0] === 0x89 && bin[1] === 0x50;
        return jpg || png ? new Blob([bin], {type: jpg ? "image/jpeg" : "image/png"}) : null } catch { return null }
    }).filter(Boolean);
    if (!photos.length && raw.length > MAX_BYTES) return json({ok: false, error: "отчёт слишком большой"}, 413);

    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    const day = new Date().toISOString().slice(0, 10);
    if (await bump("ip:" + ip, PER_IP_WINDOW) > PER_IP) return json({ok: false, error: "слишком много отчётов подряд"}, 429);
    if (await bump("day:" + day, 86400) > PER_DAY) return json({ok: false, error: "сегодня отчётов уже слишком много — попробуй завтра"}, 429);

    const t = r.tech && typeof r.tech === "object" ? r.tech : null;
    const idea = r.kind === "idea";
    const lines = [
      idea ? `💡 <b>Идея для ScanHub ${html(cut(r.version, 20))}</b>` : `🐞 <b>Ошибка в ScanHub ${html(cut(r.version, 20))}</b>`,
      "",
      `<b>${idea ? "Что предлагает" : "Что случилось"}:</b>\n${html(cut(r.text, 1500))}`,
    ];
    if (r.steps) lines.push("", `<b>Что делал перед этим:</b>\n${html(cut(r.steps, 900))}`);
    if (r.contact) lines.push("", `<b>Связаться:</b> ${html(cut(r.contact, 120))}`);
    if (t) {
      lines.push("", `<b>Windows:</b> ${html(cut(t.windows, 120))} · Python ${html(cut(t.python, 20))}`);
      if (t["где"]) lines.push(`<b>Раздел:</b> ${html(cut(t["где"], 80))}`);
      if (t["ошибка_на_экране"]) lines.push(`<b>Ошибка на экране:</b> ${html(cut(t["ошибка_на_экране"], 500))}`);
    }
    const text = lines.join("\n").slice(0, 4000);
    try {
      await tg(env, "sendMessage", JSON.stringify({chat_id: env.CHAT_ID, text, parse_mode: "HTML", disable_web_page_preview: true}))
        .catch(async () => {                            // на случай, если HTML не понравился Telegram — простым текстом
          await tg(env, "sendMessage", JSON.stringify({chat_id: env.CHAT_ID, text: text.replace(/<[^>]+>/g, "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&")}));
        });
    } catch (e) {
      console.log("telegram:", e.message);             // видно в журнале Worker на Cloudflare
      return json({ok: false, error: "не получилось переслать отчёт автору — попробуй позже"}, 502);
    }

    // снимки экрана — альбомом сразу после сообщения
    if (photos.length) {
      const fd = new FormData();
      fd.append("chat_id", String(env.CHAT_ID));
      if (photos.length === 1) {
        fd.append("photo", photos[0], "screen" + (photos[0].type === "image/png" ? ".png" : ".jpg"));
        fd.append("caption", "Снимок к сообщению выше");
        await tg(env, "sendPhoto", fd).catch(e => console.log("photo:", e.message));
      } else {
        fd.append("media", JSON.stringify(photos.map((p, i) => ({type: "photo", media: `attach://p${i}`, ...(i ? {} : {caption: "Снимки к сообщению выше"})}))));
        photos.forEach((p, i) => fd.append(`p${i}`, p, `screen${i}` + (p.type === "image/png" ? ".png" : ".jpg")));
        await tg(env, "sendMediaGroup", fd).catch(e => console.log("photos:", e.message));
      }
    }

    // журнал ошибок целиком — файлом, чтобы не упираться в длину сообщения
    const log = t && t["последние_ошибки_ScanHub"];
    if (log && log !== "журнал ошибок пуст") {
      const fd = new FormData();
      fd.append("chat_id", String(env.CHAT_ID));
      fd.append("document", new Blob([cut(log, 20000)], {type: "text/plain"}), `scanhub-${cut(r.version, 20)}-errors.txt`);
      fd.append("caption", "Последние ошибки ScanHub у этого человека");
      await tg(env, "sendDocument", fd).catch(() => {});
    }
    return json({ok: true});
  },
};
