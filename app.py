import os
import requests
import time
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# API anahtarını ortam değişkeninden oku
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.json
    url_to_analyze = data.get('url')

    if not url_to_analyze:
        return jsonify({'result': 'Hata: URL bulunamadı.'}), 400

    if not VIRUSTOTAL_API_KEY:
        return jsonify({'status': 'error', 'message': 'API anahtarı bulunamadı. Lütfen ortam değişkenlerini kontrol edin.'}), 500

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "url": url_to_analyze
    }
    
    try:
        response = requests.post(VIRUSTOTAL_URL, headers=headers, json=payload)
        response.raise_for_status()

        result_id = response.json().get("data").get("id")
        
        check_url = f"{VIRUSTOTAL_URL}/reports/{result_id}"

        for _ in range(10):
            analysis_response = requests.get(check_url, headers=headers)
            analysis_response.raise_for_status()
            analysis_data = analysis_response.json().get("data")
            
            if analysis_data:
                attributes = analysis_data.get("attributes")
                status = attributes.get("status")

                if status == "completed":
                    stats = attributes.get("last_analysis_stats")
                    malicious = stats.get("malicious", 0)

                    if malicious > 0:
                        message = f"{malicious} antivirüs sağlayıcısı bu URL'yi kötü amaçlı olarak işaretledi."
                        return jsonify({'status': 'danger', 'message': message})
                    else:
                        message = "Bu URL güvenli görünüyor."
                        return jsonify({'status': 'safe', 'message': message})
                elif status in ["queued", "in-progress"]:
                    time.sleep(1)
                    continue
                else:
                    return jsonify({'status': 'pending', 'message': 'Analiz durumu bilinmiyor. Lütfen daha sonra tekrar deneyin.'})
            
            time.sleep(1)

        return jsonify({'status': 'pending', 'message': 'Analiz hala devam ediyor. Lütfen daha sonra tekrar deneyin.'})

    except requests.exceptions.RequestException as e:
        return jsonify({'status': 'error', 'message': f'İstek hatası: {e}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Beklenmedik bir hata oluştu: {e}'})

if __name__ == '__main__':
    app.run(debug=True)