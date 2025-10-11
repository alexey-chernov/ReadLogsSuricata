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
import sqlite3

app = Flask(__name__)

# Шлях до файлу бази даних SQLite
DB_FILE = '/var/log/suricata/suricata_logs.db'

# --- ОПИС ТИПІВ ПОДІЙ ---
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
    'drop': 'Інформація про пакети, які були відкинуті Suricata в режимі IPS.',
    'quic': 'Інформація про QUIC-трафік, що використовує UDP.',
    'ftp': 'Інформація про сесії протоколу FTP (File Transfer Protocol).',
    'smtp': 'Інформація про сесії протоколу SMTP (Simple Mail Transfer Protocol).',
    'smb': 'Інформація про сесії протоколу SMB (Server Message Block).',
    'tftp': 'Інформація про сесії протоколу TFTP (Trivial File Transfer Protocol).',
    'rdp': 'Інформація про сесії протоколу RDP (Remote Desktop Protocol).',
    'ipp': 'Інформація про сесії протоколу IPP (Internet Printing Protocol).',
    'capture': 'Інформація, пов’язана з помилками захоплення пакетів (наприклад, dropped packets).'
}

# --- ФУНКЦІЇ ДЛЯ РОБОТИ З БАЗОЮ ДАНИХ ---
def get_db_connection():
    """Створює та повертає з'єднання з базою даних."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Помилка підключення до бази даних: {e}")
        return None

def get_data_from_db(query, params=()):
    """Виконує SQL-запит і повертає результати у вигляді DataFrame."""
    conn = get_db_connection()
    if conn is None:
        return pd.DataFrame()
    
    try:
        df = pd.read_sql_query(query, conn, params=params)
        return df
    except pd.io.sql.DatabaseError as e:
        print(f"Помилка виконання запиту: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

# --- ФУНКЦІЇ ВІЗУАЛІЗАЦІЇ (без змін) ---
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
    plt.ylabel('')
    plt.savefig(output_path)
    plt.close()

def create_top_alerts_bar_chart_and_save(df, top_n, output_path):
    if df.empty or 'event_type' not in df.columns: return
    alerts_df = df[df['event_type'] == 'alert']
    if alerts_df.empty: return
    if top_n == 0:
        signatures = alerts_df['signature'].value_counts()        
    else:
        signatures = alerts_df['signature'].value_counts().head(top_n)        
    plt.figure(figsize=(12, 7))
    signatures.plot(kind='bar')    
    plt.xlabel('Сигнатура')
    plt.ylabel('Кількість')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def create_line_chart_and_save(df, output_path):
    if df.empty or 'timestamp' not in df.columns: return
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    events_over_time = df.set_index('timestamp').resample('H').size()
    plt.figure(figsize=(12, 7))
    events_over_time.plot(kind='line')
    plt.xlabel('Час')
    plt.ylabel('Кількість подій')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def create_top_alert_ips_bar_chart_and_save(df, top_n, output_path):
    if df.empty: return
    alerts_df = df[df['event_type'] == 'alert']
    if alerts_df.empty: return
    if top_n == 0:
        top_ips = alerts_df['src_ip'].value_counts()        
    else:
        top_ips = alerts_df['src_ip'].value_counts().head(top_n)
    plt.figure(figsize=(12, 7))
    top_ips.plot(kind='bar')    
    plt.xlabel('IP-адреса')
    plt.ylabel('Кількість тривог')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def get_whois_info(ip_address):
    try:
        whois_info = whois.whois(ip_address)
        if whois_info and not isinstance(whois_info, dict):
            return whois_info.__dict__
        return whois_info
    except Exception as e:
        print(f"Помилка при отриманні WHOIS інформації: {e}")
        return {'error': 'WHOIS інформацію не знайдено.'}

def get_geo_info(ip_address):
    geo_db_path = os.path.join(app.root_path, 'GeoLite2-City.mmdb')
    geo_info = {}
    if os.path.exists(geo_db_path):
        try:
            reader = geoip2.database.Reader(geo_db_path)
            response = reader.city(ip_address)
            geo_info = {
                'city': response.city.name,
                'country': response.country.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
        except geoip2.errors.AddressNotFoundError:
            geo_info = {'error': 'Географічну інформацію не знайдено.'}
        except Exception as e:
            geo_info = {'error': f'Помилка GeoIP: {e}'}
        finally:
            if reader:
                reader.close()
    else:
        geo_info = {'error': 'База даних GeoLite2 не знайдена. Перевірте файл GeoLite2-City.mmdb.'}
    return geo_info

def get_geo_info_for_ips(ips):
    geo_info = []
    db_path = os.path.join(app.root_path, 'GeoLite2-City.mmdb')
    db_url = "https://cdn.jsdelivr.net/gh/wp-statistics/GeoLite2-City@2025.07/GeoLite2-City.mmdb.gz"
    if not os.path.exists(db_path):
        try:
            r = requests.get(db_url, stream=True)
            r.raise_for_status()
            import gzip
            with open(db_path, 'wb') as f:
                with gzip.open(r.raw, 'rb') as g:
                    f.write(g.read())
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

# --- МАРШРУТИ FLASK ---
@app.route('/')
def index():
    query = "SELECT * FROM events"
    data_frame = get_data_from_db(query)
    
    if data_frame.empty:
        return "Не вдалося завантажити дані з бази даних.", 500
    
    pie_chart_path = os.path.join(app.root_path, 'static', 'pie_chart.png')
    bar_chart_path = os.path.join(app.root_path, 'static', 'bar_chart.png')
    line_chart_path = os.path.join(app.root_path, 'static', 'line_chart.png')
    
    create_pie_chart_and_save(data_frame, pie_chart_path)
    create_top_alerts_bar_chart_and_save(data_frame, 10, bar_chart_path)
    create_line_chart_and_save(data_frame, line_chart_path)
    
    return render_template('index.html',
                           pie_chart='/static/pie_chart.png',
                           bar_chart='/static/bar_chart.png',
                           line_chart='/static/line_chart.png',
                           event_descriptions=event_descriptions)

@app.route('/date_filter')
def date_filter():
    selected_date = request.args.get('date')
    
    if not selected_date:
        return render_template('date_filter.html', selected_date=None, error_message=None)
    
    query = "SELECT * FROM events WHERE substr(timestamp, 0, 11) = ?"
    data_frame = get_data_from_db(query, (selected_date,))
    
    if data_frame.empty:
        return render_template('date_filter.html', selected_date=selected_date, error_message=f"Дані за {selected_date} не знайдено.")

    date_prefix = selected_date.replace('-', '_')
    pie_chart_path = os.path.join(app.root_path, 'static', f'pie_chart_{date_prefix}.png')
    bar_chart_path = os.path.join(app.root_path, 'static', f'bar_chart_{date_prefix}.png')
    line_chart_path = os.path.join(app.root_path, 'static', f'line_chart_{date_prefix}.png')
    top_alert_ips_chart_path = os.path.join(app.root_path, 'static', f'top_alert_ips_chart_{date_prefix}.png')
    
    create_pie_chart_and_save(data_frame, pie_chart_path)
    create_top_alerts_bar_chart_and_save(data_frame, 0, bar_chart_path)
    create_line_chart_and_save(data_frame, line_chart_path)
    create_top_alert_ips_bar_chart_and_save(data_frame, 0, top_alert_ips_chart_path)

    geo_data = []
    alerts_df = data_frame[data_frame['event_type'] == 'alert']
    if not alerts_df.empty:
        top_ips = alerts_df['src_ip'].value_counts()
        if not top_ips.empty:
            geo_data = get_geo_info_for_ips(top_ips)
        
    return render_template('date_filter.html',
                           selected_date=selected_date,
                           pie_chart=f'/static/pie_chart_{date_prefix}.png',
                           bar_chart=f'/static/bar_chart_{date_prefix}.png',
                           line_chart=f'/static/line_chart_{date_prefix}.png',
                           top_alert_ips_chart=f'/static/top_alert_ips_chart_{date_prefix}.png',
                           geo_data=geo_data,
                           error_message=None)
                           
@app.route('/ip/<ip_address>')
def ip_details(ip_address):
    query = "SELECT * FROM events WHERE src_ip = ? OR dest_ip = ?"
    data_frame = get_data_from_db(query, (ip_address, ip_address))
    
    if not data_frame.empty:
        data_frame['timestamp'] = pd.to_datetime(data_frame['timestamp'])
        ip_activity_list = data_frame.to_dict('records')
    else:
        ip_activity_list = []

    whois_info = get_whois_info(ip_address)
    geo_info = get_geo_info(ip_address)

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

# ЕТАП 1.1: Сторінка з усіма типами подій
@app.route('/event_types')
def event_types():
    return render_template('event_types.html', event_descriptions=event_descriptions)

# ЕТАП 1.2: Сторінка з IP-адресами для вибраного типу події
@app.route('/event_type/<event_type>')
def ips_by_event_type(event_type):
    query = "SELECT DISTINCT src_ip, dest_ip FROM events WHERE event_type = ?"
    data_frame = get_data_from_db(query, (event_type,))
    
    ips = set()
    for _, row in data_frame.iterrows():
        if row['src_ip']:
            ips.add(row['src_ip'])
        if row['dest_ip']:
            ips.add(row['dest_ip'])
            
    return render_template('ips_by_event_type.html', ips=sorted(list(ips)), event_type=event_type)
    
# ЕТАП 2.1: Сторінка з усіма сигнатурами
@app.route('/all_signatures')
def all_signatures():
    query = "SELECT DISTINCT signature FROM events WHERE signature IS NOT NULL"
    data_frame = get_data_from_db(query)
    signatures = data_frame['signature'].tolist()
    return render_template('all_signatures.html', signatures=signatures)
    
# ЕТАП 2.2: Сторінка з IP-адресами для вибраної сигнатури
@app.route('/signature/<signature>')
def ips_by_signature(signature):
    query = "SELECT DISTINCT src_ip FROM events WHERE signature = ?"
    data_frame = get_data_from_db(query, (signature,))
    ips = data_frame['src_ip'].tolist()
    return render_template('ips_by_signature.html', ips=sorted(list(set(ips))), signature=signature)

# ЕТАП 3: Сторінка з усіма IP-адресами з тривогами
@app.route('/all_alert_ips')
def all_alert_ips():
    query = "SELECT src_ip, COUNT(src_ip) as count FROM events WHERE event_type = 'alert' GROUP BY src_ip ORDER BY count DESC"
    data_frame = get_data_from_db(query)
    
    geo_data = get_geo_info_for_ips(data_frame.set_index('src_ip')['count'])
    
    return render_template('all_alert_ips.html', geo_data=geo_data)

if __name__ == '__main__':
    app.run(debug=True)
