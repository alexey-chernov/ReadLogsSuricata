import sqlite3
import json
import os
import sys

# Шляхи до файлів
EVE_JSON_FILE = '/var/log/suricata/eve.json'
DB_FILE = '/var/log/suricata/suricata_logs.db'

def create_table(conn):
    """Створює таблицю 'events' у базі даних, якщо вона не існує."""
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            proto TEXT,
            signature TEXT,
            severity INTEGER,
            alert_action TEXT,
            host TEXT,
            url TEXT,
            http_user_agent TEXT
        )
    ''')
    conn.commit()
    print("Таблицю 'events' успішно створено або вона вже існує.")

def insert_log_entry(cursor, entry):
    """Вставляє один запис лога у базу даних."""
    cursor.execute('''
        INSERT INTO events (
            timestamp, event_type, src_ip, src_port, dest_ip, dest_port,
            proto, signature, severity, alert_action, host, url, http_user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        entry.get('timestamp'),
        entry.get('event_type'),
        entry.get('src_ip'),
        entry.get('src_port'),
        entry.get('dest_ip'),
        entry.get('dest_port'),
        entry.get('proto'),
        entry.get('signature'),
        entry.get('severity'),
        entry.get('alert_action'),
        entry.get('host'),
        entry.get('url'),
        entry.get('http_user_agent')
    ))

def import_data(conn):
    """Зчитує дані з eve.json рядок за рядком і додає їх до бази даних."""
    if not os.path.exists(EVE_JSON_FILE):
        print(f"Помилка: Файл {EVE_JSON_FILE} не знайдено.")
        sys.exit(1)

    print(f"Починаємо імпорт даних з {EVE_JSON_FILE}...")
    cursor = conn.cursor()
    total_lines = 0
    imported_count = 0
    try:
        with open(EVE_JSON_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                total_lines += 1
                try:
                    event = json.loads(line)
                    # Отримання даних з різних типів подій
                    entry = {
                        'timestamp': event.get('timestamp'),
                        'event_type': event.get('event_type'),
                        'src_ip': event.get('src_ip'),
                        'src_port': event.get('src_port'),
                        'dest_ip': event.get('dest_ip'),
                        'dest_port': event.get('dest_port'),
                        'proto': event.get('proto'),
                        'signature': event.get('alert', {}).get('signature'),
                        'severity': event.get('alert', {}).get('severity'),
                        'alert_action': event.get('alert', {}).get('action'),
                        'host': event.get('http', {}).get('hostname'),
                        'url': event.get('http', {}).get('url'),
                        'http_user_agent': event.get('http', {}).get('http_user_agent')
                    }
                    insert_log_entry(cursor, entry)
                    imported_count += 1
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Сталася помилка під час читання файлу: {e}")
        conn.close()
        sys.exit(1)

    conn.commit()
    print(f"Імпорт завершено. Всього рядків у файлі: {total_lines}, успішно імпортовано: {imported_count}.")
    
def main():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        create_table(conn)
        import_data(conn)
    except sqlite3.Error as e:
        print(f"Помилка SQLite: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    main()