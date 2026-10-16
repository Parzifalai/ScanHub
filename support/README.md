# Приём отчётов «Нашёл ошибку?»

Кнопка «Нашёл ошибку?» в ScanHub отправляет отчёт на посредник — Cloudflare Worker из `cloudflare-worker.js`, — а он пересылает его автору в Telegram. Ключ Telegram-бота хранится только в Worker, поэтому в открытом коде ScanHub его нет.

Что получает автор: текст, который человек написал сам, версию ScanHub и Windows, раздел, где была ошибка, и последние ошибки из журнала ScanHub (`data\errors.log`). Имя пользователя, имя компьютера, почта и ключи вычищаются ещё на компьютере, и человек видит отчёт целиком до отправки.

## Как поднять свой приём отчётов (для форков)

1. Создай бота в [@BotFather](https://t.me/BotFather) (`/newbot`) и нажми «Старт» в чате с ним.
2. Узнай свой числовой ID в Telegram, например у [@userinfobot](https://t.me/userinfobot).
3. На [dash.cloudflare.com](https://dash.cloudflare.com) (бесплатный аккаунт): **Workers & Pages → Create → Create Worker** → «Hello World» → **Deploy** → **Edit code**, замени код на `cloudflare-worker.js` → **Deploy**.
4. В Worker: **Settings → Variables and Secrets** → **Add**:
   - `BOT_TOKEN` — тип **Secret**, ключ бота;
   - `CHAT_ID` — тип **Text**, твой ID.
5. Адрес Worker вида `https://….workers.dev` + `/report` впиши в `report.py` → `REPORT_URL` (или в `data\config.json` → `report_url`).

Ограничения от спама: не больше 5 отчётов за 10 минут с одного адреса и 200 за сутки, отчёт до 24 КБ. Бесплатного тарифа Cloudflare (100 000 запросов в сутки) хватает с запасом.
