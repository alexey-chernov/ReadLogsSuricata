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
import io
import base64

app = Flask(__name__)

# Шлях до файлу бази даних SQLite
DB_FILE = '/var/log/suricata/suricata_logs.db'
# Шлях до бази GeoLite2 (потрібна для гео-визначення)
GEOIP_DB_PATH = 'GeoLite2-City.mmdb' 

# Допоміжна функція для отримання даних з SQLite
def get_data_from_db(query, params=()):
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        return df
    except Exception as e:
        print(f"Помилка при виконанні SQL-запиту: {e}")
        return pd.DataFrame()

# --- ДОПОМІЖНІ ФУНКЦІЇ ДЛЯ ГЕНЕРАЦІЇ ГРАФІКІВ ---
def generate_chart(df, chart_type, x_col, y_col, title, label_format=''):
    if df.empty:
        return ""
    
    plt.figure(figsize=(10, 6))
    
    if chart_type == 'pie':
        # Перевірка, щоб уникнути помилки, якщо всі значення 0
        total = df[y_col].sum()
        if total == 0:
            return ""
        
        plt.pie(df[y_col], labels=df[x_col], autopct='%1.1f%%', startangle=90)
        plt.title(title)
        plt.legend(title="Типи подій", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
        plt.tight_layout()
    elif chart_type == 'bar':
        plt.bar(df[x_col], df[y_col], color='skyblue')
        plt.xlabel(x_col)
        plt.ylabel(y_col)
        plt.title(title)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
    elif chart_type == 'line':
        plt.plot(df[x_col], df[y_col], marker='o', linestyle='-', color='blue')
        plt.xlabel("Час")
        plt.ylabel("Кількість подій")
        plt.title(title)
        plt.xticks(rotation=45, ha='right')
        plt.grid(True)
        plt.tight_layout()

    # Збереження графіка в base64
    img = io.BytesIO()
    plt.savefig(img, format='png')
    plt.close()
    img.seek(0)
    return base64.b64encode(img.getvalue()).decode()

def generate_pie_chart(df):
    return generate_chart(df, 'pie', 'event_type', 'count', 'Розподіл типів подій Suricata')

def generate_bar_chart(df):
    return generate_chart(df, 'bar', 'signature', 'count', 'Топ 10 сигнатур тривог')

def generate_line_chart(df):
    return generate_chart(df, 'line', 'hour', 'count', 'Кількість подій у часі')

def generate_alert_ips_chart(df):
    return generate_chart(df, 'bar', 'src_ip', 'count', 'Топ 10 IP-адрес з тривогами')

def generate_droped_ips_chart(df):
    return generate_chart(df, 'bar', 'src_ip', 'count', 'Топ 10 IP-адрес, пакети з яких відкинуті')

def get_whois_info(ip_address):
    try:
        whois_info = whois.whois(ip_address)
        if whois_info and not isinstance(whois_info, dict):
            return whois_info.__dict__
        return whois_info
    except Exception as e:
        print(f"Помилка при отриманні WHOIS інформації: {e}")
        return {'error': 'WHOIS інформацію не знайдено.'}

def get_geo_data(df):
    geo_data_list = []
    if not os.path.exists(GEOIP_DB_PATH):
        return geo_data_list # Повертаємо порожній список, якщо база GeoIP недоступна
        
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
        for _, row in df.iterrows():
            ip = row['src_ip']
            count = row['count']
            city = 'N/A'
            country = 'N/A'
            latitude = None
            longitude = None
            
            try:
                response = reader.city(ip)
                city = response.city.name or 'Unknown City'
                country = response.country.name or 'Unknown Country'
                latitude = response.location.latitude
                longitude = response.location.longitude
            except geoip2.errors.AddressNotFoundError:
                pass # Не знайдено географічних даних для IP
            except Exception as e:
                print(f"Помилка GeoIP для {ip}: {e}")
                
            geo_data_list.append({
                'ip': ip,
                'count': count,
                'city': city,
                'country': country,
                'latitude': latitude,
                'longitude': longitude
            })
        reader.close()
    except Exception as e:
        print(f"Помилка ініціалізації GeoIP: {e}")
    
    # Сортування за кількістю
    return sorted(geo_data_list, key=lambda x: x['count'], reverse=True)


# --- ОСНОВНА ФУНКЦІЯ АНАЛІЗУ (ОНОВЛЕНО) ---
def process_analysis_from_db(filter_date=None):
    
    filter_params = []
    
    # Фільтр для всіх подій
    all_events_filter = ""
    if filter_date:
        all_events_filter = " WHERE SUBSTR(timestamp, 1, 10) = ?"        
        filter_params.append(filter_date)
    
    # Фільтр для alert-подій
    alert_filter = " WHERE event_type = 'alert' AND signature IS NOT NULL"
    drop_filter = " WHERE event_type = 'drop' AND signature IS NOT NULL"
    alert_params = []
    if filter_date:
         alert_filter += " AND SUBSTR(timestamp, 1, 10) = ?"
         drop_filter += " AND SUBSTR(timestamp, 1, 10) = ?"
         alert_params.append(filter_date)

    # 1. Розподіл типів подій (Pie Chart)
    query_pie = f"SELECT event_type, count(event_type) AS count FROM events {all_events_filter} GROUP BY event_type ORDER BY count DESC"
    df_pie = get_data_from_db(query_pie, filter_params)
    pie_chart = generate_pie_chart(df_pie)

    # 2. Сигнатури тривог (Bar Chart)
    query_bar = f"SELECT signature, count(signature) AS count FROM events {alert_filter} GROUP BY signature ORDER BY count DESC LIMIT 10"
    df_bar = get_data_from_db(query_bar, alert_params)
    bar_chart = generate_bar_chart(df_bar)

    # 3. Кількість подій у часі (Line Chart)
    # Групуємо по годині (перші 13 символів ISO дати: YYYY-MM-DDTHH)
    if filter_date:
        query_line = f"SELECT SUBSTR(timestamp, 12, 2) AS hour, COUNT(timestamp) AS count FROM events {all_events_filter} GROUP BY hour ORDER BY hour"
    else:
        query_line = "SELECT SUBSTR(timestamp, 1, 10) AS hour, COUNT(timestamp) AS count FROM events GROUP BY hour ORDER BY hour"
    df_line = get_data_from_db(query_line, filter_params)
    line_chart = generate_line_chart(df_line)

    # 4. Географічна інформація та Топ IP з тривогами
    query_geo_ips = f"SELECT src_ip, COUNT(src_ip) AS count FROM events {alert_filter} AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 10"
    df_geo_ips = get_data_from_db(query_geo_ips, alert_params)
    
    geo_data = get_geo_data(df_geo_ips)
    top_alert_ips_chart = generate_alert_ips_chart(df_geo_ips)
    
    # 4.1 Географічна інформація та Топ IP, пакети яких відкинуті
    query_geo_ips = f"SELECT src_ip, COUNT(src_ip) AS count FROM events {drop_filter} AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 10"
    df_geo_ips = get_data_from_db(query_geo_ips, alert_params)

    geo_data = get_geo_data(df_geo_ips)
    top_droped_ips_chart = generate_droped_ips_chart(df_geo_ips)

    return pie_chart, bar_chart, line_chart, geo_data, top_alert_ips_chart, top_droped_ips_chart


# --- Маршрути Flask ---
@app.route('/', methods=['GET', 'POST'])
def index():
    # Головна сторінка без фільтрації (аналіз за весь період)
    
    pie_chart, bar_chart, line_chart, geo_data, top_alert_ips_chart, top_droped_ips_chart = process_analysis_from_db()
    return render_template('index.html', 
                           pie_chart=pie_chart, 
                           bar_chart=bar_chart,
                           line_chart=line_chart, 
                           geo_data=geo_data,
                           top_alert_ips_chart=top_alert_ips_chart,
                           top_droped_ips_chart=top_droped_ips_chart)

# ЕТАП 1: Сторінка з типами подій
@app.route('/event_types')
def event_types():
    query1 = "SELECT events.event_type, count(events.event_type) AS count, event_description.description "
    query2 = "FROM events LEFT JOIN event_description ON events.event_type = event_description.event_type " 
    query3 = "GROUP BY events.event_type ORDER BY count DESC"
    data_frame = get_data_from_db(query1 + query2 + query3)
    events_with_count = data_frame.to_dict('records')    
    return render_template('event_types.html', event_descriptions=events_with_count)

# ЕТАП 1.1: Сторінка з IP-адресами для вибраного типу події
@app.route('/event_type/<event_type>')
def ips_by_event_type(event_type):    
    query = "SELECT src_ip, dest_ip FROM events WHERE event_type = ?"
    data_frame = get_data_from_db(query, (event_type,))
    ips = set()
    for _, row in data_frame.iterrows():
        if row['src_ip']:
            ips.add(row['src_ip'])
        if row['dest_ip']:
            ips.add(row['dest_ip'])            
    return render_template('ips_by_event_type.html', ips=sorted(list(ips)), event_type=event_type)

# ЕТАП 1.2: Сторінка з типами подій по заданій даті
@app.route('/event_types_with_date/<filter_date>')
def event_types_with_date(filter_date):    
    query1 = "SELECT events.event_type, count(events.event_type) AS count, event_description.description "
    query2 = "FROM events LEFT JOIN event_description ON events.event_type = event_description.event_type " 
    query3 = f" WHERE SUBSTR(timestamp, 1, 10) = '{filter_date}' GROUP BY events.event_type ORDER BY count DESC"
    data_frame = get_data_from_db(query1 + query2 + query3)
    events_with_count = data_frame.to_dict('records')    
    return render_template('event_types.html', event_descriptions=events_with_count, filter_date=filter_date)

# ЕТАП 1.3: Сторінка з IP-адресами для вибраного типу події по заданій даті
@app.route('/event_type_with_date/<event_type>/<filter_date>')
def ips_by_event_type_with_date(event_type, filter_date):    
    query = f"SELECT src_ip, dest_ip FROM events WHERE event_type = ? AND SUBSTR(timestamp, 1, 10) = '{filter_date}'"
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
    # Запит для отримання сигнатури та кількості її спрацьовувань
    query = "SELECT signature AS namesig, count(signature) AS cs FROM events WHERE signature IS NOT NULL GROUP BY signature ORDER BY cs DESC"
    data_frame = get_data_from_db(query)
    signatures_with_count = data_frame.to_dict('records')
    return render_template('all_signatures.html', signatures=signatures_with_count)
    
# ЕТАП 2.2: Сторінка з IP-адресами для вибраної сигнатури та по заданій даті
@app.route('/signature/<signature>/<filter_date>')
def ips_by_signature(signature, filter_date):
    query = f"SELECT DISTINCT src_ip FROM events WHERE event_type = 'alert' AND signature = ? AND SUBSTR(timestamp, 1, 10) = '{filter_date}'"    
    data_frame = get_data_from_db(query, (signature,))
    ips = data_frame['src_ip'].tolist()
    return render_template('ips_by_signature.html', ips=sorted(list(set(ips))), signature=signature)

# ЕТАП 2.2a: Сторінка з IP-адресами для вибраної сигнатури
@app.route('/allsignature/<signature>')
def ips_by_allsignature(signature):
    query = "SELECT DISTINCT src_ip FROM events WHERE event_type = 'alert' AND signature = ?"
    data_frame = get_data_from_db(query, (signature,))
    ips = data_frame['src_ip'].tolist()
    return render_template('ips_by_signature.html', ips=sorted(list(set(ips))), signature=signature)

# ЕТАП 2.3: Сторінка з усіма сигнатурами по заданій даті
@app.route('/all_signatures_with_date/<filter_date>')
def all_signatures_with_date(filter_date):
    query1 = "SELECT signature AS namesig, count(signature) AS cs FROM events WHERE event_type = 'alert' AND signature IS NOT NULL"
    query2 = f" AND SUBSTR(timestamp, 1, 10) = '{filter_date}' GROUP BY signature ORDER BY cs DESC"
    data_frame = get_data_from_db(query1 + query2)
    signatures_with_count = data_frame.to_dict('records')
    return render_template('all_signatures.html', signatures=signatures_with_count, filter_date=filter_date)

# ЕТАП 3: Сторінка з усіма IP-адресами з тривогами
@app.route('/all_alert_ips')
def all_alert_ips():
    query = "SELECT src_ip, COUNT(src_ip) as count FROM events WHERE event_type = 'alert' AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC"
    df_geo_ips = get_data_from_db(query)
    geo_data = get_geo_data(df_geo_ips)
    return render_template('all_alert_ips.html', geo_data=geo_data)

# ЕТАП 3.1: Сторінка з усіма IP-адресами, пакети яких відкинуті
@app.route('/all_droped_ips')
def all_droped_ips():
    query = "SELECT src_ip, COUNT(src_ip) as count FROM events WHERE event_type = 'drop' AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC"
    df_geo_ips = get_data_from_db(query)
    geo_data = get_geo_data(df_geo_ips)
    return render_template('all_droped_ips.html', geo_data=geo_data)

# ЕТАП 3.2: Сторінка з усіма IP-адресами з тривогами для заданої дати
@app.route('/all_alert_ips_with_date/<filter_date>')
def all_alert_ips_with_date(filter_date):
    query1 = "SELECT src_ip, COUNT(src_ip) as count FROM events WHERE event_type = 'alert'"
    query2 = f" AND SUBSTR(timestamp, 1, 10) = '{filter_date}' AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC"
    df_geo_ips = get_data_from_db(query1 + query2)
    geo_data = get_geo_data(df_geo_ips)
    return render_template('all_alert_ips.html', geo_data=geo_data)

# ЕТАП 3.3: Сторінка з усіма IP-адресами, пакети яких відкинуті для заданої дати
@app.route('/all_droped_ips_with_date/<filter_date>')
def all_droped_ips_with_date(filter_date):
    query1 = "SELECT src_ip, COUNT(src_ip) as count FROM events WHERE event_type = 'drop'"
    query2 = f" AND SUBSTR(timestamp, 1, 10) = '{filter_date}' AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC"
    df_geo_ips = get_data_from_db(query1 + query2)
    geo_data = get_geo_data(df_geo_ips)
    return render_template('all_droped_ips.html', geo_data=geo_data)

# ЕТАП 4: СТОРІНКА ФІЛЬТРАЦІЇ ПО ДАТІ (ОНОВЛЕНО)
@app.route('/date_filter', methods=['GET', 'POST'])
def date_filter():
    filter_date = None
    pie_chart = bar_chart = line_chart = top_alert_ips_chart = None
    bar_chart = top_droped_ips_chart = None
    geo_data = []

    if request.method == 'POST':
        filter_date = request.form.get('filter_date')
        if filter_date:      
            # Викликаємо функцію аналізу з датою фільтрації
            pie_chart, bar_chart, line_chart, geo_data, top_alert_ips_chart, top_droped_ips_chart = process_analysis_from_db(filter_date)
        
    return render_template('date_filter.html', 
                           pie_chart=pie_chart, 
                           bar_chart=bar_chart,
                           line_chart=line_chart, 
                           geo_data=geo_data,
                           top_alert_ips_chart=top_alert_ips_chart,
                           top_droped_ips_chart=top_droped_ips_chart,
                           filter_date=filter_date)

# ЕТАП 5: СТОРІНКА ІНФОРМАЦІ ПО ЗАДАНУ IP-АДРЕСУ
@app.route('/ip_info', methods=['GET', 'POST'])
def ip_info():
    ipaddress = whois_info = None
    geo_info = {}
    ip_activity = {}
                           
    if request.method == 'POST':
        ipaddress = request.form.get('ipaddress')
        if ipaddress:      
            # 1. WHOIS-інформація
            whois_info = get_whois_info(ipaddress)

            # 2. Географічна інформація
            geo_info = {}
            if os.path.exists(GEOIP_DB_PATH):
                try:
                    reader = geoip2.database.Reader(GEOIP_DB_PATH)
                    response = reader.city(ipaddress)
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

            # 3. Активність за IP
            data_frame = get_data_from_db(f"SELECT * FROM events")
            
            # Перетворюємо стовпець 'timestamp' на об'єкти datetime
            if 'timestamp' in data_frame.columns:
                data_frame['timestamp'] = pd.to_datetime(data_frame['timestamp'], errors='coerce')

            ip_activity = data_frame[(data_frame['src_ip'] == ipaddress) | (data_frame['dest_ip'] == ipaddress)]
            ip_activity = ip_activity.to_dict('records')

            if whois_info and not isinstance(whois_info, dict):
                whois_info = whois_info.__dict__
            else:
                whois_info = whois_info
        
    return render_template('ip_info.html',
                           ip_address=ipaddress,
                           whois_info=whois_info,
                           geo_info=geo_info,
                           ip_activity=ip_activity)

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
            error_message = f"Помилка читання файлу fast.log: {e}"
    return render_template('fast_log.html', log_content=log_content, error_message=error_message)

@app.route('/ip_details/<ip_address>/<event_type>')
def ip_details(ip_address, event_type):
    # 1. WHOIS-інформація
    whois_info = get_whois_info(ip_address)

    # 2. Географічна інформація
    geo_info = {}
    if os.path.exists(GEOIP_DB_PATH):
        try:
            reader = geoip2.database.Reader(GEOIP_DB_PATH)
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

    # 3. Активність за IP
    data_frame = get_data_from_db(f"SELECT * FROM events WHERE event_type = '{event_type}'")
    
    # Перетворюємо стовпець 'timestamp' на об'єкти datetime
    if 'timestamp' in data_frame.columns:
        data_frame['timestamp'] = pd.to_datetime(data_frame['timestamp'], errors='coerce')

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

if __name__ == '__main__':    
    app.run(debug=True)