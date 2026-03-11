import os
import json
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ======================================
# API ключ из переменной окружения
# ======================================

VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    raise ValueError("Добавьте переменную окружения VT_API_KEY")

# ======================================
# Загрузка Suricata логов
# ======================================

log_file = "alerts-only.json"

with open(log_file, "r") as f:
    logs = json.load(f)

df = pd.json_normalize(logs)

print("Логи загружены")
print(df.head())

# ======================================
# Извлечение IP
# ======================================

ips = df["src_ip"].dropna().unique()

print("\nНайденные IP:")
print(ips)

# ======================================
# Функция VirusTotal
# ======================================

def check_ip_virustotal(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ip": ip,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"]
        }

    else:

        print(f"Ошибка проверки {ip}")
        return None


# ======================================
# Анализ IP
# ======================================

results = []

print("\nПроверка IP через VirusTotal...")

for ip in ips:

    result = check_ip_virustotal(ip)

    if result:
        results.append(result)

results_df = pd.DataFrame(results)

print(results_df)

# ======================================
# Реагирование на угрозы
# ======================================

THRESHOLD = 2

for _, row in results_df.iterrows():

    if row["malicious"] >= THRESHOLD:

        print(f"\n⚠ ОБНАРУЖЕНА УГРОЗА")
        print(f"IP: {row['ip']}")
        print(f"Malicious detections: {row['malicious']}")
        print(f"🚫 блокировка IP {row['ip']}")

# ======================================
# Сохранение отчета
# ======================================

results_df.to_csv("threat_report.csv", index=False)
results_df.to_json("threat_report.json", orient="records", indent=4)

print("\nОтчет сохранен")

# ======================================
# Построение графика
# ======================================

if not results_df.empty:

    plt.figure(figsize=(10,5))

    top_ips = results_df.sort_values("malicious", ascending=False).head(5)

    sns.barplot(data=top_ips, x="ip", y="malicious")

    plt.title("Топ 5 вредоносных IP")
    plt.xticks(rotation=45)

    plt.tight_layout()

    plt.savefig("threat_graph.png")

    plt.show()

    print("График сохранен")
