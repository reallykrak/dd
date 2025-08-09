import os
import hashlib
import time
import vt
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
from config import TELEGRAM_BOT_TOKEN, VT_API_KEY

# VT client
vt_client = vt.Client(VT_API_KEY)

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
    file_path = f"downloads/{file.file_name}"

    # Download
    os.makedirs("downloads", exist_ok=True)
    file.get_file().download(file_path)
    update.message.reply_text("📥 Dosya indirildi, tarama başlıyor...")

    # Hash al
    file_hash = sha256_of_file(file_path)

    # Önce hash ile sorgula
    try:
        report = vt_client.get_object(f"/files/{file_hash}")
    except vt.error.APIError:
        # Yoksa yükle
        with open(file_path, "rb") as f:
            analysis = vt_client.scan_file(f)
            analysis_id = analysis.id
        update.message.reply_text("⏳ Yükledim, analiz bekleniyor...")
        for _ in range(15):
            analysis = vt_client.get_object(f"/analyses/{analysis_id}")
            if analysis.status == "completed":
                break
            time.sleep(2)
        report = vt_client.get_object(f"/files/{file_hash}")

    # Sonuçları çıkar
    detections = report.last_analysis_stats
    positives = detections["malicious"]
    total = sum(detections.values())

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
