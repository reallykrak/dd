import os
import time
import hashlib
import requests
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
from config import TELEGRAM_BOT_TOKEN, VT_API_KEY

def sha256_of_file(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def start(update: Update, context: CallbackContext):
    update.message.reply_text("🛡️ Merhaba! Bana bir dosya gönder, VirusTotal ile tarayayım.")

def handle_document(update: Update, context: CallbackContext):
    file = update.message.document
    os.makedirs("downloads", exist_ok=True)
    file_path = f"downloads/{file.file_name}"

    update.message.reply_text("📥 Dosya indiriliyor...")
    file_obj = context.bot.get_file(file.file_id)
    file_obj.download(file_path)

    update.message.reply_text("🔍 Tarama başlatılıyor...")
    file_hash = sha256_of_file(file_path)

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(url, headers=headers)

    if resp.status_code == 200:
        data = resp.json()
    else:
        with open(file_path, "rb") as f:
            files = {"file": (file.file_name, f)}
            resp = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
            analysis_id = resp.json()["data"]["id"]

        update.message.reply_text("⏳ Dosya VirusTotal'a yüklendi, analiz bekleniyor...")

        for _ in range(30):
            check = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()
            if check["data"]["attributes"]["status"] == "completed":
                break
            time.sleep(2)
        else:
            update.message.reply_text("⚠️ Analiz çok uzun sürdü, daha sonra tekrar dene.")
            return

        resp = requests.get(url, headers=headers)
        data = resp.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]
    positives = stats["malicious"]
    total = sum(stats.values())

    if positives > 0:
        update.message.reply_text(f"🔴 Zararlı: {positives}/{total} — {file.file_name}")
    else:
        update.message.reply_text(f"🟢 Temiz: {positives}/{total} — {file.file_name}")

def main():
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(MessageHandler(Filters.document, handle_document))

    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
