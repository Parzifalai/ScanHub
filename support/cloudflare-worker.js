// Посредник для «Нашёл ошибку?» в ScanHub: принимает отчёт и пересылает его автору в Telegram.
// Ключ бота хранится только здесь (секрет BOT_TOKEN в настройках Worker), в открытом коде ScanHub его нет.
//
// Настройки Worker (Settings → Variables and Secrets):
//   BOT_TOKEN — секрет: ключ бота от @BotFather
//   CHAT_ID   — кому пересылать: числовой ID автора в Telegram
//
// Защита от спама: не больше 5 отчётов за 10 минут с одного адреса и 200 за сутки всего, отчёт до 24 КБ.

const PER_IP = 5, PER_IP_WINDOW = 600, PER_DAY = 200, MAX_BYTES = 24 * 1024;

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

export default {
  async fetch(req, env){
    const url = new URL(req.url);
    if (req.method === "GET") return new Response("ScanHub: приём отчётов об ошибках работает", {headers: {"Content-Type": "text/plain; charset=utf-8"}});
    if (req.method !== "POST" || url.pathname !== "/report") return json({ok: false, error: "не найдено"}, 404);
    if (!env.BOT_TOKEN || !env.CHAT_ID) return json({ok: false, error: "посредник не настроен"}, 500);

    const len = Number(req.headers.get("Content-Length") || 0);
    if (len > MAX_BYTES) return json({ok: false, error: "отчёт слишком большой"}, 413);
    const raw = await req.text();
    if (raw.length > MAX_BYTES) return json({ok: false, error: "отчёт слишком большой"}, 413);
    let r;
    try { r = JSON.parse(raw) } catch { return json({ok: false, error: "неверный отчёт"}, 400) }
    if (r?.app !== "scanhub" || typeof r.text !== "string" || r.text.trim().length < 5) return json({ok: false, error: "пустой отчёт"}, 400);

    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    const day = new Date().toISOString().slice(0, 10);
    if (await bump("ip:" + ip, PER_IP_WINDOW) > PER_IP) return json({ok: false, error: "слишком много отчётов подряд"}, 429);
    if (await bump("day:" + day, 86400) > PER_DAY) return json({ok: false, error: "сегодня отчётов уже слишком много — попробуй завтра"}, 429);

    const t = r.tech && typeof r.tech === "object" ? r.tech : null;
    const lines = [
      `🐞 <b>Ошибка в ScanHub ${html(cut(r.version, 20))}</b>`,
      "",
      `<b>Что случилось:</b>\n${html(cut(r.text, 1500))}`,
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
