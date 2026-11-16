import pandas as pd
import json
import matplotlib
matplotlib.use('Agg')  # Обов'язково до імпорту pyplot!
import matplotlib.pyplot as plt
import os
import re
from flask import Flask, render_template, request, redirect, url_for
import geoip2.database
import requests
from requests.exceptions import RequestException
import whois
from datetime import datetime
import psycopg2
from psycopg2 import sql
from sqlalchemy import create_engine
import io
import base64

app = Flask(__name__)

# Параметри підключення до PostgreSQL
with open('config.json', 'r', encoding='utf-8') as config_file:
    DB_CONFIG = json.load(config_file)

#Створення SQLAlchemy engine для зручної роботи з pandas.read_sql_query
DB_URI = f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}"
db_engine = create_engine(DB_URI)

# Шлях до бази GeoLite2 (потрібна для гео-визначення)
GEOIP_DB_PATH = 'GeoLite2-City.mmdb'

def normalize_jsonb(value):
    """Повертає (parsed_obj, pretty_json_str) для поля JSONB."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None, ""

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value, value
    else:
        parsed = value

    pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
    return parsed, pretty

def get_table_name(filter_date=None):
    """
    Повертає назву таблиці events_YYYYMM.
    Якщо дата фільтрації задана (YYYY-MM-DD), використовує її рік та місяць.
    Якщо дата не задана, повертає таблицю поточного місяця.
    """
    if filter_date:
        try:
            dt = datetime.strptime(filter_date[:10], '%Y-%m-%d')
            return f"events_{dt.strftime('%Y%m')}"
        except ValueError:
            pass
    
    # Резервний варіант: поточний місяць
    now = datetime.now()
    return f"events_{now.strftime('%Y%m')}"

# Допоміжна функція для отримання даних з PostgreSQL через Pandas
def get_data_from_db(query, params=None):
    try:
        df = pd.read_sql_query(query, db_engine, params=params)
        return df
    except Exception as e:
        print(f"Помилка при виконанні SQL-запиту: {e}")
        return pd.DataFrame()

# --- ДОПОМІЖНІ ФУНКЦІЇ ДЛЯ ГЕНЕРАЦІЇ ГРАФІКІВ ---
def generate_chart(df, chart_type, x_col, y_col, title, label_format=''):
    if df.empty:
        return ""
    # Конвертуємо стовпчик у стрічку, якщо це об'єкти IP-адрес
    df[x_col] = df[x_col].astype(str)
    
    plt.figure(figsize=(10, 6))
        
    if chart_type == 'pie':
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

    img = io.BytesIO()
    plt.savefig(img, format='png')
    plt.close()
    img.seek(0)
    return base64.b64encode(img.getvalue()).decode()

def generate_pie_chart(df):
    return generate_chart(df, 'pie', 'event_type', 'count', 'Розподіл типів подій Suricata')

def generate_bar_chart(df):
    return generate_chart(df, 'bar', 'signature', 'count', 'Топ 10 сигнатур тривог')

def generate_bar_chart_drop(df):
    return generate_chart(df, 'bar', 'signature', 'count', 'Топ 10 сигнатур відкинутих пакетів')

def generate_line_chart(df):
    return generate_chart(df, 'line', 'hour', 'count', 'Кількість подій у часі')

def generate_alert_ips_chart(df):
    return generate_chart(df, 'bar', 'dest_ip', 'count', 'Топ 10 IP-адрес з тривогами')

def generate_droped_ips_chart(df):
    return generate_chart(df, 'bar', 'dest_ip', 'count', 'Топ 10 IP-адрес, пакети з яких відкинуті')

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
        return geo_data_list
        
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
        for _, row in df.iterrows():
            ip = str(row['dest_ip'])
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
                pass
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
    
    return sorted(geo_data_list, key=lambda x: x['count'], reverse=True)


# --- ОСНОВНА ФУНКЦІЯ АНАЛІЗУ ---
def process_analysis_from_db(filter_date=None):
    table_name = get_table_name(filter_date)
    filter_params = []
    
    all_events_filter = ""
    if filter_date:
        all_events_filter = f" WHERE SUBSTR(timestamp, 1, 10) = '{filter_date}'"
        #filter_params.append(filter_date)
        
    alert_filter = " WHERE event_type = 'alert'"
    drop_filter = " WHERE event_type = 'drop'"
    alert_params = []
    
    if filter_date:
        alert_filter += f" AND SUBSTR(timestamp, 1, 10) = '{filter_date}'"
        drop_filter += f" AND SUBSTR(timestamp, 1, 10) = '{filter_date}'"
        #alert_params.append(filter_date)
        
    # 1. Розподіл типів подій (Pie Chart)
    query_pie = f"SELECT event_type, count(event_type) AS count FROM {table_name} {all_events_filter} GROUP BY event_type ORDER BY count DESC"
    df_pie = get_data_from_db(query_pie, filter_params)
    pie_chart = generate_pie_chart(df_pie)

    # 2. Сигнатури тривог (Bar Chart)
    query_bar = f"SELECT signature, count(signature) AS count FROM {table_name} {alert_filter} AND signature IS NOT NULL GROUP BY signature ORDER BY count DESC LIMIT 10"
    df_bar = get_data_from_db(query_bar, alert_params)
    bar_chart = generate_bar_chart(df_bar)

    # 2.1. Сигнатури відкинутих (Bar Chart)
    query_bar_drop = f"SELECT signature, count(signature) AS count FROM {table_name} {drop_filter} AND signature IS NOT NULL GROUP BY signature ORDER BY count DESC LIMIT 10"
    df_bar_drop = get_data_from_db(query_bar_drop, alert_params)
    bar_chart_drop = generate_bar_chart_drop(df_bar_drop)

    # 3. Кількість подій у часі (Line Chart)
    if filter_date:
        query_line = f"SELECT SUBSTR(timestamp, 12, 2) AS hour, COUNT(timestamp) AS count FROM {table_name} {all_events_filter} GROUP BY hour ORDER BY hour"
    else:
        query_line = f"SELECT SUBSTR(timestamp, 1, 10) AS hour, COUNT(timestamp) AS count FROM {table_name} GROUP BY hour ORDER BY hour"
    df_line = get_data_from_db(query_line, filter_params)
    line_chart = generate_line_chart(df_line)

    # 4. Географічна інформація та Топ IP з тривогами
    query_geo_ips = f"SELECT dest_ip, COUNT(dest_ip) AS count FROM {table_name} {alert_filter} AND dest_ip IS NOT NULL GROUP BY dest_ip ORDER BY count DESC LIMIT 10"
    df_geo_ips = get_data_from_db(query_geo_ips, alert_params)
    
    geo_data = get_geo_data(df_geo_ips)
    top_alert_ips_chart = generate_alert_ips_chart(df_geo_ips)
    
    # 4.1 Географічна інформація та Топ IP, пакети яких відкинуті
    query_geo_ips_drop = f"SELECT dest_ip, COUNT(dest_ip) AS count FROM {table_name} {drop_filter} AND dest_ip IS NOT NULL GROUP BY dest_ip ORDER BY count DESC LIMIT 10"
    df_geo_ips_drop = get_data_from_db(query_geo_ips_drop, alert_params)

    top_droped_ips_chart = generate_droped_ips_chart(df_geo_ips_drop)

    return pie_chart, bar_chart, bar_chart_drop, line_chart, geo_data, top_alert_ips_chart, top_droped_ips_chart

# --- Маршрути Flask ---
@app.route('/', methods=['GET', 'POST'])
def index():
    pie_chart, bar_chart, bar_chart_drop, line_chart, geo_data, top_alert_ips_chart, top_droped_ips_chart = process_analysis_from_db()

    return render_template('index.html', 
                           pie_chart=pie_chart, 
                           bar_chart=bar_chart,
                           bar_chart_drop=bar_chart_drop,
                           line_chart=line_chart, 
                           geo_data=geo_data,
                           top_alert_ips_chart=top_alert_ips_chart,
                           top_droped_ips_chart=top_droped_ips_chart)
    
# ЕТАП 1: Сторінка з типами подій
@app.route('/event_types')
def event_types():
    table_name = get_table_name()
    query = f"""
        SELECT events.event_type, count(events.event_type) AS count, event_description.description 
        FROM {table_name} AS events 
        LEFT JOIN event_description ON events.event_type = event_description.event_type 
        GROUP BY events.event_type, event_description.description 
        ORDER BY count DESC
    """
    data_frame = get_data_from_db(query)
    events_with_count = data_frame.to_dict('records')    
    return render_template('event_types.html', event_descriptions=events_with_count)

# ЕТАП 1.1: Сторінка з IP-адресами для вибраного типу події
@app.route('/event_type/<event_type>')
def ips_by_event_type(event_type):
    table_name = get_table_name()
    query = f"SELECT dest_ip, COUNT(dest_ip) as count FROM {table_name} WHERE event_type = %s GROUP BY dest_ip"
    data_frame = get_data_from_db(query, (event_type,))
    geo_data = get_geo_data(data_frame)
    return render_template('ips_by_event_type.html', geo_data=geo_data, event_type=event_type)

# ЕТАП 1.2: Сторінка з типами подій по заданій даті
@app.route('/event_types_with_date/<filter_date>')
def event_types_with_date(filter_date):    
    table_name = get_table_name(filter_date)
    query = f"""
        SELECT events.event_type, count(events.event_type) AS count, event_description.description 
        FROM {table_name} AS events 
        LEFT JOIN event_description ON events.event_type = event_description.event_type 
        WHERE events.timestamp::date = %s 
        GROUP BY events.event_type, event_description.description 
        ORDER BY count DESC
    """
    data_frame = get_data_from_db(query, (filter_date,))
    events_with_count = data_frame.to_dict('records')    
    return render_template('event_types.html', event_descriptions=events_with_count, filter_date=filter_date)

# ЕТАП 1.3: Сторінка з IP-адресами для вибраного типу події по заданій даті
@app.route('/event_type_with_date/<event_type>/<filter_date>')
def ips_by_event_type_with_date(event_type, filter_date):        
    table_name = get_table_name(filter_date)
    query = f"SELECT dest_ip, COUNT(dest_ip) as count FROM {table_name} WHERE event_type = %s AND timestamp::date = %s GROUP BY dest_ip"
    data_frame = get_data_from_db(query, (event_type, filter_date))    
    geo_data = get_geo_data(data_frame)           
    return render_template('ips_by_event_type.html', geo_data=geo_data, event_type=event_type)

# ЕТАП 2.1: Сторінка з усіма сигнатурами тривог
@app.route('/all_signatures')
def all_signatures():
    table_name = get_table_name()
    query = f"SELECT signature AS namesig, count(signature) AS cs FROM {table_name} WHERE event_type = 'alert' AND signature IS NOT NULL GROUP BY signature ORDER BY cs DESC"
    data_frame = get_data_from_db(query)
    signatures_with_count = data_frame.to_dict('records')
    return render_template('all_signatures.html', signatures=signatures_with_count)
    
# ЕТАП 2.2: Сторінка з IP-адресами для вибраної сигнатури та по заданій даті
@app.route('/signature/<signature>/<filter_date>')
def ips_by_signature(signature, filter_date):
    table_name = get_table_name(filter_date)
    query = f"SELECT DISTINCT dest_ip FROM {table_name} WHERE event_type = 'alert' AND signature = %s AND timestamp::date = %s"    
    data_frame = get_data_from_db(query, (signature, filter_date))
    ips = [str(ip) for ip in data_frame['dest_ip'].tolist()]
    return render_template('ips_by_signature.html', ips=sorted(list(set(ips))), signature=signature)

# ЕТАП 2.2a: Сторінка з IP-адресами для вибраної сигнатури
@app.route('/allsignature/<signature>')
def ips_by_allsignature(signature):
    table_name = get_table_name()
    query = f"SELECT DISTINCT dest_ip FROM {table_name} WHERE event_type = 'alert' AND signature = %s"
    data_frame = get_data_from_db(query, (signature,))
    ips = [str(ip) for ip in data_frame['dest_ip'].tolist()]
    return render_template('ips_by_signature.html', ips=sorted(list(set(ips))), signature=signature)

# ЕТАП 2.3: Сторінка з усіма сигнатурами по заданій даті
@app.route('/all_signatures_with_date/<filter_date>')
def all_signatures_with_date(filter_date):
    table_name = get_table_name(filter_date)
    query = f"SELECT signature AS namesig, count(signature) AS cs FROM {table_name} WHERE event_type = 'alert' AND signature IS NOT NULL AND timestamp::date = %s GROUP BY signature ORDER BY cs DESC"
    data_frame = get_data_from_db(query, (filter_date,))
    signatures_with_count = data_frame.to_dict('records')
    return render_template('all_signatures.html', signatures=signatures_with_count, filter_date=filter_date)

# ЕТАП 2.4: Сторінка з усіма сигнатурами відкинутих пакетів
@app.route('/all_signatures_drop')
def all_signatures_drops():
    table_name = get_table_name()
    query = f"SELECT signature AS namesig, count(signature) AS cs FROM {table_name} WHERE event_type = 'drop' AND signature IS NOT NULL GROUP BY signature ORDER BY cs DESC"
    data_frame = get_data_from_db(query)
    signatures_with_count = data_frame.to_dict('records')
    return render_template('all_signatures_drops.html', signatures=signatures_with_count)
    
# ЕТАП 2.5: Сторінка з IP-адресами для вибраної сигнатури відкинутих пакетів та по заданій даті
@app.route('/signature_drop/<signature>/<filter_date>')
def ips_by_signature_drop(signature, filter_date):
    table_name = get_table_name(filter_date)
    query = f"SELECT DISTINCT dest_ip FROM {table_name} WHERE event_type = 'drop' AND signature = %s AND timestamp::date = %s"    
    data_frame = get_data_from_db(query, (signature, filter_date))
    ips = [str(ip) for ip in data_frame['dest_ip'].tolist()]
    return render_template('ips_by_signature_drops.html', ips=sorted(list(set(ips))), signature=signature)

# ЕТАП 2.5a: Сторінка з IP-адресами для вибраної сигнатури відкинутих пакетів
@app.route('/allsignature_drop/<signature>')
def ips_by_allsignature_drop(signature):
    table_name = get_table_name()
    query = f"SELECT DISTINCT dest_ip FROM {table_name} WHERE event_type = 'drop' AND signature = %s"
    data_frame = get_data_from_db(query, (signature,))
    ips = [str(ip) for ip in data_frame['dest_ip'].tolist()]
    return render_template('ips_by_signature_drops.html', ips=sorted(list(set(ips))), signature=signature)

# ЕТАП 2.6: Сторінка з усіма сигнатурами відкинутих пакетів по заданій даті
@app.route('/all_signatures_drops_with_date/<filter_date>')
def all_signatures_drops_with_date(filter_date):
    table_name = get_table_name(filter_date)
    query = f"SELECT signature AS namesig, count(signature) AS cs FROM {table_name} WHERE event_type = 'drop' AND signature IS NOT NULL AND timestamp::date = %s GROUP BY signature ORDER BY cs DESC"
    data_frame = get_data_from_db(query, (filter_date,))
    signatures_with_count = data_frame.to_dict('records')
    return render_template('all_signatures_drops.html', signatures=signatures_with_count, filter_date=filter_date)

# ЕТАП 3: Сторінка з усіма IP-адресами з тривогами
@app.route('/all_alert_ips')
def all_alert_ips():
    table_name = get_table_name()
    query = f"SELECT dest_ip, COUNT(dest_ip) as count FROM {table_name} WHERE event_type = 'alert' AND dest_ip IS NOT NULL GROUP BY dest_ip ORDER BY count DESC"
    df_geo_ips = get_data_from_db(query)
    geo_data = get_geo_data(df_geo_ips)
    return render_template('all_alert_ips.html', geo_data=geo_data)

# ЕТАП 3.1: Сторінка з усіма IP-адресами, пакети яких відкинуті
@app.route('/all_droped_ips')
def all_droped_ips():
    table_name = get_table_name()
    query = f"SELECT dest_ip, COUNT(dest_ip) as count FROM {table_name} WHERE event_type = 'drop' AND dest_ip IS NOT NULL GROUP BY dest_ip ORDER BY count DESC"
    df_geo_ips = get_data_from_db(query)
    geo_data = get_geo_data(df_geo_ips)
    return render_template('all_droped_ips.html', geo_data=geo_data)

# ЕТАП 3.2: Сторінка з усіма IP-адресами з тривогами для заданої дати
@app.route('/all_alert_ips_with_date/<filter_date>')
def all_alert_ips_with_date(filter_date):
    table_name = get_table_name(filter_date)
    query = f"SELECT dest_ip, COUNT(dest_ip) as count FROM {table_name} WHERE event_type = 'alert' AND timestamp::date = %s AND dest_ip IS NOT NULL GROUP BY dest_ip ORDER BY count DESC"
    df_geo_ips = get_data_from_db(query, (filter_date,))
    geo_data = get_geo_data(df_geo_ips)
    return render_template('all_alert_ips.html', geo_data=geo_data)

# ЕТАП 3.3: Сторінка з усіма IP-адресами, пакети яких відкинуті для заданої дати
@app.route('/all_droped_ips_with_date/<filter_date>')
def all_droped_ips_with_date(filter_date):
    table_name = get_table_name(filter_date)
    query = f"SELECT dest_ip, COUNT(dest_ip) as count FROM {table_name} WHERE event_type = 'drop' AND timestamp::date = %s AND dest_ip IS NOT NULL GROUP BY dest_ip ORDER BY count DESC"
    df_geo_ips = get_data_from_db(query, (filter_date,))
    geo_data = get_geo_data(df_geo_ips)
    return render_template('all_droped_ips.html', geo_data=geo_data)

# ЕТАП 4: СТОРІНКА ФІЛЬТРАЦІЇ ПО ДАТІ
@app.route('/date_filter', methods=['GET', 'POST'])
def date_filter():
    filter_date = None
    pie_chart = bar_chart = bar_chart_drop = line_chart = top_alert_ips_chart = top_droped_ips_chart = None
    geo_data = []

    if request.method == 'POST':
        filter_date = request.form.get('filter_date')

        if filter_date:      
            pie_chart, bar_chart, bar_chart_drop, line_chart, geo_data, top_alert_ips_chart, top_droped_ips_chart = process_analysis_from_db(filter_date)
        
    return render_template('date_filter.html', 
                           pie_chart=pie_chart, 
                           bar_chart=bar_chart,
                           bar_chart_drop=bar_chart_drop,
                           line_chart=line_chart, 
                           geo_data=geo_data,
                           top_alert_ips_chart=top_alert_ips_chart,
                           top_droped_ips_chart=top_droped_ips_chart,
                           filter_date=filter_date)

# ЕТАП 5: СТОРІНКА ІНФОРМАЦІЇ ПРО ЗАДАНУ IP-АДРЕСУ
@app.route('/ip_info', methods=['GET', 'POST'])
def ip_info():
    pie_chart = ipaddress = whois_info = None
    geo_info = {}
    ip_activity = {}
    table_name = get_table_name()
                           
    if request.method == 'POST':
        ipaddress = request.form.get('ipaddress')
        if ipaddress:      
            whois_info = get_whois_info(ipaddress)

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

            # Запит типів подій
            query_pie = f"SELECT event_type, count(event_type) AS count FROM {table_name} WHERE dest_ip = %s OR src_ip = %s GROUP BY event_type ORDER BY count DESC"
            df_pie = get_data_from_db(query_pie, (ipaddress, ipaddress))
            pie_chart = generate_pie_chart(df_pie)
            
            # Активність
            data_frame = get_data_from_db(f"SELECT * FROM {table_name} WHERE dest_ip = %s OR src_ip = %s", (ipaddress, ipaddress))
            if 'timestamp' in data_frame.columns:
                data_frame['timestamp'] = pd.to_datetime(data_frame['timestamp'], errors='coerce', utc=False)

            ip_activity = data_frame.to_dict('records')

            if whois_info and not isinstance(whois_info, dict):
                whois_info = whois_info.__dict__
        
    return render_template('ip_info.html',
                           ip_address=ipaddress,
                           whois_info=whois_info,
                           geo_info=geo_info,
                           ip_activity=ip_activity,
                           pie_chart=pie_chart)

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
    whois_info = get_whois_info(ip_address)

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

    table_name = get_table_name()
    data_frame = get_data_from_db(f"SELECT * FROM {table_name} WHERE event_type = %s AND (src_ip = %s OR dest_ip = %s)", (event_type, ip_address, ip_address))    
    
    if 'timestamp' in data_frame.columns:
        data_frame['timestamp'] = pd.to_datetime(data_frame['timestamp'], errors='coerce', utc=False)
        
    ip_activity_list = data_frame.to_dict('records')

    if whois_info and not isinstance(whois_info, dict):
        whois_dict = whois_info.__dict__
    else:
        whois_dict = whois_info

    return render_template('ip_details.html',
                           ip_address=ip_address,
                           whois_info=whois_dict,
                           geo_info=geo_info,
                           ip_activity=ip_activity_list)

# Сторінка Фільтр за період
@app.route('/period_filter', methods=['GET', 'POST'])
def period_filter_page():
    logs_activity = {}
    text_period = ''

    if request.method == 'POST':
        date_from = request.form.get('filter_date_from')
        time_from = request.form.get('filter_time_from')
        date_to = request.form.get('filter_date_to')
        time_to = request.form.get('filter_time_to')

        filter_period_from = f"{date_from}T{time_from}"
        filter_period_to = f"{date_to}T{time_to}"

        text_period = f"з {date_from} {time_from} по {date_to} {time_to}"
        
        if date_from and date_to:
            table_name = get_table_name(date_from)
            query = f"SELECT * FROM {table_name} WHERE SUBSTR(timestamp, 1, 16) BETWEEN '{filter_period_from}' AND '{filter_period_to}'"

            data_frame = get_data_from_db(query, (filter_period_from, filter_period_to))            
            
            if 'timestamp' in data_frame.columns:
                data_frame['timestamp'] = pd.to_datetime(data_frame['timestamp'], errors='coerce', utc=False)
            
            logs_activity = data_frame.to_dict('records')
                        
    return render_template('period_info.html', dataframe=logs_activity, period=text_period)

# Сторінка детальної інфоррмації про певну подію
@app.route("/event_details/<int:event_id>")
def event_details(event_id):
    table_name = get_table_name()

    if not re.fullmatch(r"[A-Za-z0-9_]+", table_name):
        raise ValueError(f"Некоректна назва таблиці: {table_name}")

    query = f'SELECT * FROM "{table_name}" WHERE id = %s'
    data_frame = get_data_from_db(query, (event_id,))

    if data_frame is None or data_frame.empty:
        return render_template("event_details.html", event=None, event_id=event_id)

    if "timestamp" in data_frame.columns:
        data_frame["timestamp"] = pd.to_datetime(
            data_frame["timestamp"], errors="coerce"
        )

    event_record = data_frame.iloc[0].to_dict()
    details_obj, details_pretty = normalize_jsonb(event_record.get("event_details"))

    return render_template(
        "event_details.html",
        event=event_record,
        event_details_obj=details_obj,
        event_details_pretty=details_pretty,
    )


if __name__ == '__main__':    
    app.run(debug=True)
