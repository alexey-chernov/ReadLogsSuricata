import pandas as pd
import json
import matplotlib.pyplot as plt
import os
import re
from flask import Flask, render_template, request, redirect, url_for
import geoip2.database
import requests
from requests.exceptions import RequestException
import whois
from datetime import datetime

app = Flask(__name__)

# --- ОПИС ТИПІВ ПОДІЙ (без змін) ---
event_descriptions = {
    'stats': 'Статистичні дані про роботу Suricata (трафік, кількість подій тощо).',
    'flow': 'Інформація про мережеві сесії (потоки) TCP, UDP, ICMP.',
    'dns': 'Інформація про DNS-запити та відповіді.',
    'http': 'Інформація про HTTP-трафік (запити, відповіді, заголовки).',
    'alert': 'Сигнали тривоги про виявлену підозрілу активність, що відповідає правилам IDS/IPS.',
    'fileinfo': 'Інформація про передачу файлів через мережу.',
    'tls': 'Інформація про TLS/SSL сесії.',
    'ssh': 'Інформація про сесії протоколу SSH.',
    'mdns': 'Інформація про запити та відповіді протоколу mDNS (Multicast DNS).',
    'drop': 'Інформація про пакети, які були відкинуті Suricata в режимі IPS.'
}

# --- Оновлена функція для аналізу eve.json з можливістю фільтрації за датою ---
def process_eve_json_for_analysis(file_path, filter_date=None):
    if not os.path.exists(file_path):
        return None
    events = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not events:
        return None
    df = pd.DataFrame(events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    if filter_date:
        try:
            date_to_filter = datetime.strptime(filter_date, '%Y-%m-%d').date()
            df = df[df['timestamp'].dt.date == date_to_filter]
        except (ValueError, TypeError):
            # Якщо дата некоректна, повертаємо порожній DataFrame
            return pd.DataFrame()
            
    return df

# --- Інші функції візуалізації (без змін) ---
def create_pie_chart_and_save(df, output_path):
    if df.empty or 'event_type' not in df.columns: return
    event_counts = df['event_type'].value_counts()
    threshold = 0.02
    total_count = event_counts.sum()
    large_sectors = event_counts[event_counts / total_count > threshold]
    if len(large_sectors) < len(event_counts):
        other_count = event_counts[event_counts / total_count <= threshold].sum()
        large_sectors['Інше'] = other_count
    plt.figure(figsize=(8, 8))
    plt.pie(large_sectors, labels=large_sectors.index, autopct='%1.1f%%', startangle=90)
    plt.title('Розподіл типів подій Suricata')
    plt.ylabel('')
    plt.savefig(output_path)
    plt.close()

def create_top_alerts_bar_chart_and_save(df, top_n, output_path):
    if df.empty or 'event_type' not in df.columns: return
    alerts_df = df[df['event_type'] == 'alert']
    if alerts_df.empty: return
    signatures = alerts_df['alert'].apply(lambda x: x.get('signature') if isinstance(x, dict) else None)
    top_signatures = signatures.value_counts().head(top_n)
    plt.figure(figsize=(12, 7))
    top_signatures.plot(kind='bar')
    plt.title(f'Топ-{top_n} сигнатур тривог')
    plt.xlabel('Сигнатура')
    plt.ylabel('Кількість')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def create_line_chart_and_save(df, output_path):
    if df.empty or 'timestamp' not in df.columns: return
    events_over_time = df.set_index('timestamp').resample('H').size()
    plt.figure(figsize=(12, 7))
    events_over_time.plot(kind='line')
    plt.title('Кількість подій у часі')
    plt.xlabel('Число')
    plt.ylabel('Кількість подій')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def create_top_alert_ips_bar_chart_and_save(df, top_n, output_path):
    if df.empty: return
    alerts_df = df[df['event_type'] == 'alert']
    if alerts_df.empty: return
    top_ips = alerts_df['src_ip'].value_counts().head(top_n)
    plt.figure(figsize=(12, 7))
    top_ips.plot(kind='bar')
    plt.title(f'Топ-{top_n} IP-адрес за кількістю тривог')
    plt.xlabel('IP-адреса')
    plt.ylabel('Кількість тривог')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def get_geo_info_for_ips(ips):
    geo_info = []
    db_path = os.path.join(app.root_path, 'GeoLite2-City.mmdb')
    #db_url = "https://cdn.jsdelivr.net/gh/wp-statistics/GeoLite2-City@2025.07/GeoLite2-City.mmdb.gz"
    db_url = "https://git.io/GeoLite2-City.mmdb"
    if not os.path.exists(db_path):
        try:
            r = requests.get(db_url, stream=True)
            r.raise_for_status()            
        except RequestException:
            pass
    try:
        reader = geoip2.database.Reader(db_path)
        for ip in ips.index:
            try:
                response = reader.city(ip)
                geo_info.append({
                    'ip': ip,
                    'count': ips[ip],
                    'city': response.city.name or 'N/A',
                    'country': response.country.name or 'N/A',
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude
                })
            except geoip2.errors.AddressNotFoundError:
                geo_info.append({
                    'ip': ip,
                    'count': ips[ip],
                    'city': 'Не знайдено',
                    'country': 'Не знайдено',
                    'latitude': None,
                    'longitude': None
                })
        reader.close()
    except Exception:
        pass
    return geo_info

@app.route('/')
def index():
    eve_file_path = '/var/log/suricata/eve.json'
    data_frame = process_eve_json_for_analysis(eve_file_path)
    if data_frame is None:
        return "Не вдалося завантажити дані з eve.json", 500
    
    # Решта коду для генерації графіків (без змін)
    pie_chart_path = os.path.join(app.root_path, 'static', 'pie_chart.png')
    bar_chart_path = os.path.join(app.root_path, 'static', 'bar_chart.png')
    line_chart_path = os.path.join(app.root_path, 'static', 'line_chart.png')
    top_alert_ips_chart_path = os.path.join(app.root_path, 'static', 'top_alert_ips_chart.png')
    create_pie_chart_and_save(data_frame, pie_chart_path)
    create_top_alerts_bar_chart_and_save(data_frame, 20, bar_chart_path)
    create_line_chart_and_save(data_frame, line_chart_path)
    create_top_alert_ips_bar_chart_and_save(data_frame, 20, top_alert_ips_chart_path)
    geo_data = []
    alerts_df = data_frame[data_frame['event_type'] == 'alert']
    if not alerts_df.empty:
        top_ips = alerts_df['src_ip'].value_counts().head(20)
        if not top_ips.empty:
            geo_data = get_geo_info_for_ips(top_ips)
    return render_template('index.html',
                           pie_chart='/static/pie_chart.png',
                           bar_chart='/static/bar_chart.png',
                           line_chart='/static/line_chart.png',
                           top_alert_ips_chart='/static/top_alert_ips_chart.png',
                           geo_data=geo_data,
                           event_descriptions=event_descriptions)

# --- НОВИЙ МАРШРУТ ДЛЯ ФІЛЬТРАЦІЇ ЗА ДАТОЮ ---
@app.route('/date_filter')
def date_filter():
    selected_date = request.args.get('date')
    
    # Якщо дата не вказана, відображаємо порожню сторінку з формою
    if not selected_date:
        return render_template('date_filter.html', selected_date=None, error_message=None)
    
    eve_file_path = '/var/log/suricata/eve.json'
    data_frame = process_eve_json_for_analysis(eve_file_path, filter_date=selected_date)
    
    if data_frame is None:
        return render_template('date_filter.html', selected_date=selected_date, error_message="Не вдалося завантажити дані з eve.json.")
        
    if data_frame.empty:
        return render_template('date_filter.html', selected_date=selected_date, error_message=f"Дані за {selected_date} не знайдено.")

    # Генерація унікальних імен файлів для графіків, щоб уникнути конфліктів
    date_prefix = selected_date.replace('-', '_')
    pie_chart_path = os.path.join(app.root_path, 'static', f'pie_chart_{date_prefix}.png')
    bar_chart_path = os.path.join(app.root_path, 'static', f'bar_chart_{date_prefix}.png')
    line_chart_path = os.path.join(app.root_path, 'static', f'line_chart_{date_prefix}.png')
    top_alert_ips_chart_path = os.path.join(app.root_path, 'static', f'top_alert_ips_chart_{date_prefix}.png')
    
    # Створення графіків з відфільтрованого DataFrame
    create_pie_chart_and_save(data_frame, pie_chart_path)
    create_top_alerts_bar_chart_and_save(data_frame, 20, bar_chart_path)
    create_line_chart_and_save(data_frame, line_chart_path)
    create_top_alert_ips_bar_chart_and_save(data_frame, 20, top_alert_ips_chart_path)

    # Отримання географічних даних
    geo_data = []
    alerts_df = data_frame[data_frame['event_type'] == 'alert']
    if not alerts_df.empty:
        top_ips = alerts_df['src_ip'].value_counts().head(20)
        if not top_ips.empty:
            geo_data = get_geo_info_for_ips(top_ips)

    return render_template('date_filter.html',
                           selected_date=selected_date,
                           pie_chart=f'/static/pie_chart_{date_prefix}.png',
                           bar_chart=f'/static/bar_chart_{date_prefix}.png',
                           line_chart=f'/static/line_chart_{date_prefix}.png',
                           top_alert_ips_chart=f'/static/top_alert_ips_chart_{date_prefix}.png',
                           geo_data=geo_data,
                           event_descriptions=event_descriptions,
                           error_message=None)
                           
# --- Інші існуючі маршрути (без змін) ---
@app.route('/ip/<ip_address>')
def ip_details(ip_address):
    eve_file_path = '/var/log/suricata/eve.json'
    data_frame = process_eve_json_for_analysis(eve_file_path)
    if data_frame is None:
        return "Не вдалося завантажити дані з eve.json", 500
    try:
        whois_info = whois.whois(ip_address)
    except Exception as e:
        whois_info = {'error': str(e)}
    geo_info = {}
    db_path = os.path.join(app.root_path, 'GeoLite2-City.mmdb')
    if os.path.exists(db_path):
        try:
            reader = geoip2.database.Reader(db_path)
            response = reader.city(ip_address)
            geo_info = {
                'city': response.city.name or 'N/A',
                'country': response.country.name or 'N/A',
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
            reader.close()
        except Exception:
            geo_info = {'error': 'Географічну інформацію не знайдено.'}
    else:
        geo_info = {'error': 'База даних GeoLite2 не знайдена.'}
    ip_activity = data_frame[(data_frame['src_ip'] == ip_address) | (data_frame['dest_ip'] == ip_address)]
    ip_activity_list = ip_activity.to_dict('records')
    if whois_info and not isinstance(whois_info, dict):
        whois_dict = whois_info.__dict__
    else:
        whois_dict = whois_info
    return render_template('ip_details.html',
                           ip_address=ip_address,
                           whois_info=whois_dict,
                           geo_info=geo_info,
                           ip_activity=ip_activity_list)
    
@app.route('/fast-log')
def fast_log_page():
    fast_log_file_path = '/var/log/suricata/fast.log'

    log_content = ""
    error_message = None

    if not os.path.exists(fast_log_file_path):
        error_message = "Файл fast.log не знайдено або він недоступний."
    else:
        try:
            with open(fast_log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
        except Exception as e:
            error_message = f"Помилка при читанні файлу: {e}"

    return render_template('fast_log.html',
                           log_content=log_content,
                           error_message=error_message)


if __name__ == '__main__':
    app.run(debug=True)