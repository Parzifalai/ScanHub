🇷🇺 [Русская версия](README.ru.md)

# Receiving "Found a bug?" reports

The "Found a bug?" button in ScanHub sends a report to an intermediary, a Cloudflare Worker from `cloudflare-worker.js`, which forwards it to the author on Telegram. The Telegram bot key lives only in the Worker, so it is not in ScanHub's open source code.

What the author receives: the text the user wrote, the ScanHub and Windows versions, the section where the error occurred, and the latest errors from the ScanHub log (`data\errors.log`). The user name, computer name, email and keys are scrubbed on the computer itself, and the user sees the whole report before it is sent.

## Setting up your own report receiver (for forks)

1. Create a bot with [@BotFather](https://t.me/BotFather) (`/newbot`) and press "Start" in the chat with it.
2. Find your numeric Telegram ID, for example with [@userinfobot](https://t.me/userinfobot).
3. On [dash.cloudflare.com](https://dash.cloudflare.com) (a free account): **Workers & Pages → Create → Create Worker** → "Hello World" → **Deploy** → **Edit code**, replace the code with `cloudflare-worker.js` → **Deploy**.
4. In the Worker: **Settings → Variables and Secrets** → **Add**:
   - `BOT_TOKEN` — type **Secret**, the bot key;
   - `CHAT_ID` — type **Text**, your ID.
5. Put the Worker address (`https://….workers.dev`) + `/report` into `report.py` → `REPORT_URL` (or into `data\config.json` → `report_url`).

Spam limits: no more than 5 reports per 10 minutes and 200 per day from one address, and a report is at most 24 KB. The Cloudflare free tier (100,000 requests per day) is more than enough.


## Updating the intermediary (wrangler)

```
npm i -g wrangler
cd support
wrangler login
wrangler deploy
```

`wrangler.toml` is already configured: the name is `scanhub-reports`, the counter storage is `USAGE`, and a summary goes to Telegram once a day. `CHAT_ID` is set on the Cloudflare site and is preserved on deploy (`keep_vars`). Secrets are set once: `wrangler secret put BOT_TOKEN`, `wrangler secret put STATS_KEY`. Statistics: `https://<address>.workers.dev/stats?key=<STATS_KEY>`.
