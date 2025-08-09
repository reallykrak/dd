import os
import time
import hashlib
import requests
import magic
from telegram import Update, ParseMode
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
from config import TELEGRAM_BOT_TOKEN, VT_API_KEY

def sha256_of_file(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def virus_total_scan(file_path, file_name):
    file_hash = sha256_of_file(file_path)
    headers = {"x-apikey": VT_API_KEY}
    url_report = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    resp = requests.get(url_report, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
    else:
        with open(file_path, "rb") as f:
            files = {"file": (file_name, f)}
            upload_resp = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
            if upload_resp.status_code != 200:
                return "❌ Dosya VirusTotal'a yüklenemedi."
            analysis_id = upload_resp.json()["data"]["id"]

        for _ in range(30):  # 30*2 saniye = 60 saniye max bekleme
            check = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()
            if check["data"]["attributes"]["status"] == "completed":
                break
            time.sleep(2)
        else:
            return "⏳ Analiz zaman aşımına uğradı, lütfen tekrar deneyin."

        resp = requests.get(url_report, headers=headers)
        if resp.status_code != 200:
            return "❌ Analiz sonucu alınamadı."
        data = resp.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]
    engines = data["data"]["attributes"]["last_analysis_results"]

    # Emoji ile tespit durumu
    results_text = []
    for engine, result in engines.items():
        detected = result["category"] == "malicious"
        emoji = "🔴" if detected else "✅"
        name = engine
        results_text.append(f"{emoji} {name}")

    # Dosya bilgisi
    try:
        file_type = magic.from_file(file_path, mime=True)
    except:
        file_type = "Bilinmiyor"

    file_size_mb = os.path.getsize(file_path) / (1024*1024)

    vt_link = f"https://www.virustotal.com/gui/file/{file_hash}/detection"

    message = (
        f"🧬 *Tespitler:* {stats['malicious']} / {sum(stats.values())}\n\n"
        + "\n".join(results_text) +
        f"\n\n🔖 *Dosya adı:* {file_name}"
        f"\n🔒 *Dosya türü:* {file_type}"
        f"\n📁 *Dosya boyutu:* {file_size_mb:.2f} MB"
        f"\n\n🎉 Magic\n• File\n\n⚜️ [VirusTotal linki]({vt_link})"
    )
    return message

def start(update: Update, context: CallbackContext):
    update.message.reply_text("🛡️ Merhaba! Bana bir dosya gönder, hızlıca VirusTotal ile tarayayım.")

def handle_document(update: Update, context: CallbackContext):
    file = update.message.document
    os.makedirs("downloads", exist_ok=True)
    file_path = f"downloads/{file.file_id}_{file.file_name}"

    update.message.reply_text("📥 Dosya indiriliyor...")
    file_obj = context.bot.get_file(file.file_id)
    file_obj.download(file_path)

    update.message.reply_text("🔍 Tarama başlatılıyor...")

    result_text = virus_total_scan(file_path, file.file_name)

    update.message.reply_text(result_text, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

def main():
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(MessageHandler(Filters.document, handle_document))

    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
