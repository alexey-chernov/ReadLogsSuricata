from datetime import datetime
import json
import os
import sys
import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json, execute_values

# Шлях до файлу логів Suricata
EVE_JSON_FILE = "/var/log/suricata/eve.json"

# Параметри підключення до PostgreSQL
with open("config.json", "r", encoding="utf-8") as config_file:
  DB_CONFIG = json.load(config_file)


def sanitize_json_value(value):
  """Рекурсивно видаляє символи \u0000, які викликають помилку в PostgreSQL."""
  if isinstance(value, str):
    return value.replace("\x00", "")
  if isinstance(value, list):
    return [sanitize_json_value(item) for item in value]
  if isinstance(value, dict):
    return {k: sanitize_json_value(v) for k, v in value.items()}
  return value


def get_or_create_table(conn, created_tables, table_name):
  """
    Динамічно створює таблицю events_РРРРММ та індекси (включно з GIN для JSONB),
    якщо вона ще не була створена під час поточного сеансу.
    """
  if table_name in created_tables:
    return

  with conn.cursor() as cursor:
    create_table_query = sql.SQL("""
            CREATE TABLE IF NOT EXISTS {table} (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type VARCHAR(50) NOT NULL,
                src_ip INET,
                src_port INTEGER,
                dest_ip INET,
                dest_port INTEGER,
                proto VARCHAR(20),
                signature TEXT,
                severity INTEGER,
                alert_action VARCHAR(50),
                host TEXT,
                url TEXT,
                http_user_agent TEXT,
                event_details JSONB
            );
            CREATE INDEX IF NOT EXISTS {idx_ts} ON {table} (timestamp);
            CREATE INDEX IF NOT EXISTS {idx_src} ON {table} (src_ip);
            CREATE INDEX IF NOT EXISTS {idx_dst} ON {table} (dest_ip);
            CREATE INDEX IF NOT EXISTS {idx_gin} ON {table} USING GIN (event_details jsonb_path_ops);
        """).format(
        table=sql.Identifier(table_name),
        idx_ts=sql.Identifier(f"idx_{table_name}_ts"),
        idx_src=sql.Identifier(f"idx_{table_name}_src"),
        idx_dst=sql.Identifier(f"idx_{table_name}_dst"),
        idx_gin=sql.Identifier(f"idx_{table_name}_details_gin"),
    )
    cursor.execute(create_table_query)

  conn.commit()
  created_tables.add(table_name)


def extract_table_name(ts_string):
  """Отримує назву таблиці у форматі events_РРРРММ із ISO-рядка часу."""
  if not ts_string:
    now = datetime.now()
    return f"events_{now.strftime('%Y%m')}"

  year_month = ts_string[:7].replace("-", "")
  return f"events_{year_month}"


def build_record(event, event_type):
  """Формує кортеж значень для вставки в таблицю."""
  alert_obj = event.get("alert") or {}
  http_obj = event.get("http") or {}

  raw_details = event.get(event_type)
  clean_details = (
      sanitize_json_value(raw_details) if raw_details is not None else None
  )

  return (
      event.get("timestamp"),
      event_type,
      event.get("src_ip"),
      event.get("src_port"),
      event.get("dest_ip"),
      event.get("dest_port"),
      event.get("proto"),
      alert_obj.get("signature"),
      alert_obj.get("severity"),
      alert_obj.get("action"),
      http_obj.get("hostname"),
      http_obj.get("url"),
      http_obj.get("http_user_agent"),
      Json(clean_details) if clean_details is not None else None,
  )


def flush_batch(cursor, table_name, records):
  """Виконує швидку вставку через psycopg2.extras.execute_values."""
  insert_query = sql.SQL("""
        INSERT INTO {table} (
            timestamp, event_type, src_ip, src_port, dest_ip, dest_port,
            proto, signature, severity, alert_action, host, url, http_user_agent,
            event_details
        ) VALUES %s
    """).format(table=sql.Identifier(table_name))

  execute_values(cursor, insert_query, records, page_size=len(records))


def import_data(conn):
  """Зчитує дані з eve.json та записує їх пакетами в PostgreSQL."""
  if not os.path.exists(EVE_JSON_FILE):
    print(f"Помилка: Файл {EVE_JSON_FILE} не знайдено.")
    sys.exit(1)

  print(f"Починаємо імпорт даних з {EVE_JSON_FILE}...")

  created_tables = set()
  batches = {}
  batch_size = 5000

  total_lines = 0
  imported_count = 0

  try:
    with open(EVE_JSON_FILE, "r", encoding="utf-8") as f, conn.cursor() as cursor:
      for line in f:
        total_lines += 1
        line = line.strip()
        if not line:
          continue

        try:
          event = json.loads(line)
        except json.JSONDecodeError:
          continue

        if not isinstance(event, dict):
          continue

        event_type = event.get("event_type")
        if not event_type or event_type == "stats":
          continue

        ts = event.get("timestamp")
        table_name = extract_table_name(ts)
        get_or_create_table(conn, created_tables, table_name)

        record = build_record(event, event_type)

        if table_name not in batches:
          batches[table_name] = []

        batches[table_name].append(record)
        imported_count += 1

        if len(batches[table_name]) >= batch_size:
          flush_batch(cursor, table_name, batches[table_name])
          batches[table_name].clear()

      for table_name, records in batches.items():
        if records:
          flush_batch(cursor, table_name, records)

    conn.commit()
    print(
        f"Імпорт завершено. Усього рядків: {total_lines}, успішно імпортовано:"
        f" {imported_count}."
    )

  except Exception as e:
    print(f"Сталася помилка під час імпорту: {e}")
    conn.rollback()
    raise


def main():
  conn = None
  try:
    conn = psycopg2.connect(**DB_CONFIG)
    import_data(conn)
  except psycopg2.Error as e:
    print(f"Помилка PostgreSQL: {e}")
    sys.exit(1)
  except Exception as e:
    print(f"Критична помилка: {e}")
    sys.exit(1)
  finally:
    if conn and not conn.closed:
      conn.close()


if __name__ == "__main__":
  main()