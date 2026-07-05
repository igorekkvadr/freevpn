#!/usr/bin/env python3
import re
import requests
import socket
import time
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote

# Источники
BLACK_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt"
BLACK_MOBILE_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt"
WHITE_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt"
KIZYAK_MOBILE_URL = "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta7.txt"
KIZYAK_PC_URL = "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6BL.txt"

MAX_WORKERS = 200
TEST_TIMEOUT = 2
CONNECTION_TIMEOUT = 1
MAX_LATENCY_MS = 2000
MAX_NETHERLANDS = 5
MAX_COUNTRIES = 10
MAX_PER_COUNTRY = 10

# Черные источники (используют черный флаг)
BLACK_SOURCES = {BLACK_URL, BLACK_MOBILE_URL, KIZYAK_PC_URL}

# Фиксированный ключ, который всегда будет первым
FIXED_KEY = "vless://7e544a9d-7667-413b-bbb0-b3bb1aac6d77@8.47.69.0:443?path=%2Frsedgws&security=tls&fragment=2,0-1,tlshello,null&encryption=none&fm=%7B%22tcp%22%3A%5B%7B%22settings%22%3A%7B%22delay%22%3A%220-1%22%2C%22length%22%3A%222%22%2C%22packets%22%3A%22tlshello%22%7D%2C%22type%22%3A%22fragment%22%7D%5D%7D&echfq=none&host=shegeftihaaa.net&allowinsecure=0&type=ws&sni=shegeftihaaa.net#🇩🇪 Germany ⭐ [🏳️]"

# Полный список стран с флагами и названиями
COUNTRIES_DATA = {
    "🇷🇺": ["russia", "россия", "ru"],
    "🇪🇪": ["estonia", "эстония", "ee"],
    "🇱🇻": ["latvia", "латвия", "lv"],
    "🇱🇹": ["lithuania", "литва", "lt"],
    "🇫🇮": ["finland", "финляндия", "fi"],
    "🇩🇪": ["germany", "германия", "de"],
    "🇸🇪": ["sweden", "швеция", "se"],
    "🇳🇱": ["netherlands", "нидерланды", "голландия", "nl"],
    "🇵🇱": ["poland", "польша", "pl"],
    "🇺🇦": ["ukraine", "украина", "ua"],
    "🇺🇸": ["usa", "united states", "сша", "америка", "us"],
    "🇬🇧": ["united kingdom", "великобритания", "uk", "gb"],
    "🇫🇷": ["france", "франция", "fr"],
    "🇪🇸": ["spain", "испания", "es"],
    "🇮🇹": ["italy", "италия", "it"],
    "🇯🇵": ["japan", "япония", "jp"],
    "🇸🇬": ["singapore", "сингапур", "sg"],
    "🇦🇺": ["australia", "австралия", "au"],
    "🇨🇦": ["canada", "канада", "ca"],
    "🇧🇷": ["brazil", "бразилия", "br"],
    "🇨🇳": ["china", "китай", "cn"],
    "🇮🇳": ["india", "индия", "in"],
    "🇰🇷": ["south korea", "korea", "южная корея", "kr"],
    "🇹🇷": ["turkey", "турция", "tr"],
    "🇦🇪": ["uae", "united arab emirates", "оаэ", "ae"],
    "🇨🇭": ["switzerland", "швейцария", "ch"],
    "🇦🇹": ["austria", "австрия", "at"],
    "🇧🇪": ["belgium", "бельгия", "be"],
    "🇳🇴": ["norway", "норвегия", "no"],
    "🇩🇰": ["denmark", "дания", "dk"],
    "🇮🇪": ["ireland", "ирландия", "ie"],
    "🇵🇹": ["portugal", "португалия", "pt"],
    "🇬🇷": ["greece", "греция", "gr"],
    "🇨🇿": ["czech republic", "чехия", "cz"],
    "🇭🇺": ["hungary", "венгрия", "hu"],
    "🇷🇴": ["romania", "румыния", "ro"],
    "🇧🇬": ["bulgaria", "болгария", "bg"],
    "🇭🇷": ["croatia", "хорватия", "hr"],
    "🇸🇰": ["slovakia", "словакия", "sk"],
    "🇸🇮": ["slovenia", "словения", "si"],
    "🇱🇺": ["luxembourg", "люксембург", "lu"],
    "🇲🇹": ["malta", "мальта", "mt"],
    "🇨🇾": ["cyprus", "кипр", "cy"],
    "🇮🇱": ["israel", "израиль", "il"],
    "🇸🇦": ["saudi arabia", "саудовская аравия", "sa"],
    "🇲🇾": ["malaysia", "малайзия", "my"],
    "🇹🇭": ["thailand", "таиланд", "th"],
    "🇻🇳": ["vietnam", "вьетнам", "vn"],
    "🇵🇭": ["philippines", "филиппины", "ph"],
    "🇮🇩": ["indonesia", "индонезия", "id"],
    "🇳🇿": ["new zealand", "новая зеландия", "nz"],
    "🇿🇦": ["south africa", "юар", "za"],
    "🇦🇷": ["argentina", "аргентина", "ar"],
    "🇨🇱": ["chile", "чили", "cl"],
    "🇨🇴": ["colombia", "колумбия", "co"],
    "🇲🇽": ["mexico", "мексика", "mx"],
    "🇪🇬": ["egypt", "египет", "eg"],
    "🇳🇬": ["nigeria", "нигерия", "ng"],
    "🇰🇿": ["kazakhstan", "казахстан", "kz"],
}

COUNTRY_BY_NAME = {}
COUNTRY_BY_FLAG = {}
for flag, names in COUNTRIES_DATA.items():
    for name in names:
        COUNTRY_BY_NAME[name] = (flag, names[0].title())
    COUNTRY_BY_FLAG[flag] = names[0].title()

def get_country_from_text(text):
    if not text:
        return "Other", "🌍"
    
    text_lower = text.lower()
    
    for flag in COUNTRIES_DATA.keys():
        if flag in text:
            return flag, COUNTRY_BY_FLAG[flag]
    
    for name, (flag, country_name) in COUNTRY_BY_NAME.items():
        if name in text_lower:
            return flag, country_name
    
    words = re.findall(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b', text)
    if words:
        for word in words:
            word_lower = word.lower()
            for name, (flag, country_name) in COUNTRY_BY_NAME.items():
                if name in word_lower:
                    return flag, country_name
    
    return "🌍", "Other"

def get_country_and_flag_from_key(key):
    if '#' not in key:
        return "Other", "🌍"
    
    try:
        fragment = unquote(key.split('#', 1)[1])
        flag, country = get_country_from_text(fragment)
        return country, flag
    except:
        return "Other", "🌍"

def fetch_keys(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        keys = []
        seen = set()  # Для удаления дубликатов
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                if any(line.startswith(proto) for proto in [
                    "vless://", "hysteria2://", "vmess://", 
                    "trojan://", "ss://", "ssr://", "tuic://",
                    "wireguard://", "openvpn://", "socks://", "http://",
                    "https://", "hy2://", "vl://"
                ]):
                    # Убираем # в конце для сравнения
                    clean_line = line.split('#')[0]
                    if clean_line not in seen:
                        seen.add(clean_line)
                        keys.append(line)
        return keys, url
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return [], url

def parse_host_port(key):
    try:
        clean_key = key.split('#')[0]
        
        if clean_key.startswith("vless://"):
            without_scheme = clean_key[len("vless://"):]
        elif clean_key.startswith("hysteria2://") or clean_key.startswith("hy2://"):
            without_scheme = clean_key[len("hysteria2://"):] if clean_key.startswith("hysteria2://") else clean_key[len("hy2://"):]
        elif clean_key.startswith("trojan://"):
            without_scheme = clean_key[len("trojan://"):]
        elif clean_key.startswith("ss://"):
            without_scheme = clean_key[len("ss://"):]
        elif clean_key.startswith("tuic://"):
            without_scheme = clean_key[len("tuic://"):]
        elif clean_key.startswith("vmess://"):
            return None, None
        else:
            return None, None
            
        at_idx = without_scheme.rfind("@")
        if at_idx == -1:
            return None, None
            
        after_at = without_scheme[at_idx + 1:]
        host_port = after_at.split("?")[0].split("/")[0]
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            return host.strip("[]"), int(port)
    except Exception:
        pass
    return None, None

def test_key(key_info):
    key, source_url = key_info
    host, port = parse_host_port(key)
    if not host:
        return None
    
    try:
        start = time.time()
        
        for family in [socket.AF_INET, socket.AF_INET6]:
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(CONNECTION_TIMEOUT)
                result = sock.connect_ex((host, port))
                sock.close()
                elapsed = round((time.time() - start) * 1000, 1)
                if result == 0 and elapsed <= MAX_LATENCY_MS:
                    return {
                        "key": key,
                        "host": host,
                        "port": port,
                        "latency_ms": elapsed,
                        "source": source_url,
                        "is_black": source_url in BLACK_SOURCES
                    }
            except:
                continue
    except Exception:
        pass
    return None

def load_old_first_seen():
    try:
        with open("docs/keys.json", "r", encoding="utf-8") as f:
            old = json.load(f)
        seen = {}
        if "all_keys" in old:
            for entry in old["all_keys"]:
                if "key" in entry and "first_seen" in entry:
                    seen[entry["key"]] = entry["first_seen"]
        return seen
    except Exception:
        return {}

def format_key_with_location(key_data, country_name, index, total_for_country):
    flag = "🌍"
    for f, name in COUNTRY_BY_FLAG.items():
        if name.lower() == country_name.lower():
            flag = f
            break
    
    color = "🏴" if key_data["is_black"] else "🏳️"
    number = f" #{index}" if total_for_country > 1 else ""
    
    location = f"{flag} {country_name}{number} [{color}]"
    
    clean_key = key_data["key"].split('#')[0]
    return f"{clean_key}#{location}"

def save_keys_with_locations(keys_data, filename, add_header=False):
    country_groups = defaultdict(list)
    
    # Добавляем фиксированный ключ в начало
    fixed_key_entry = {
        "key": FIXED_KEY,
        "is_black": False,
        "latency_ms": 0
    }
    
    # Проверяем, есть ли уже такой ключ в списке
    fixed_key_clean = FIXED_KEY.split('#')[0]
    exists = False
    for key_data in keys_data:
        if key_data["key"].split('#')[0] == fixed_key_clean:
            exists = True
            break
    
    # Если ключа нет, добавляем его в начало
    all_keys = list(keys_data)
    if not exists:
        all_keys.insert(0, fixed_key_entry)
    
    for key_data in all_keys:
        country_name, _ = get_country_and_flag_from_key(key_data["key"])
        country_groups[country_name].append(key_data)
    
    # Ограничиваем каждую страну до MAX_PER_COUNTRY ключей
    for country in country_groups:
        if len(country_groups[country]) > MAX_PER_COUNTRY:
            country_groups[country] = country_groups[country][:MAX_PER_COUNTRY]
    
    if "Netherlands" in country_groups and len(country_groups["Netherlands"]) > MAX_NETHERLANDS:
        country_groups["Netherlands"] = country_groups["Netherlands"][:MAX_NETHERLANDS]
    
    # Россия всегда в топе, остальные по количеству
    russia_keys = country_groups.pop("Russia", [])
    sorted_countries = sorted(country_groups.items(), key=lambda x: len(x[1]), reverse=True)
    top_countries = [("Russia", russia_keys)] + sorted_countries[:MAX_COUNTRIES-1] if russia_keys else sorted_countries[:MAX_COUNTRIES]
    
    lines = []
    
    if add_header:
        header = [
            "#profile-title: VPN | FREE",
            "#announce: ⚡ Бесплатный впн⚡",
            "#hide-settings: 1",
            "#profile-update-interval: 1",
            ""
        ]
        lines.extend(header)
    
    # Сначала добавляем Germany (если есть) с фиксированным ключом
    if "Germany" in country_groups:
        germany_keys = sorted(country_groups["Germany"], key=lambda x: x["latency_ms"])
        # Пропускаем уже добавленный фиксированный ключ
        for key_data in germany_keys:
            if key_data["key"] != FIXED_KEY:
                formatted_key = format_key_with_location(key_data, "Germany", 1, len(germany_keys))
                lines.append(formatted_key)
                lines.append("")
    
    # Затем остальные страны
    for country_name, keys in top_countries:
        if country_name == "Germany":
            continue  # Пропускаем, так как уже добавили
        sorted_keys = sorted(keys, key=lambda x: x["latency_ms"])
        for i, key_data in enumerate(sorted_keys, 1):
            formatted_key = format_key_with_location(key_data, country_name, i, len(sorted_keys))
            lines.append(formatted_key)
            lines.append("")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    print(f"Сохранено {len(all_keys)} ключей в {filename}")

def main():
    old_first_seen = load_old_first_seen()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    urls = [
        BLACK_URL,
        BLACK_MOBILE_URL,
        WHITE_URL,
        KIZYAK_MOBILE_URL,
        KIZYAK_PC_URL
    ]
    
    print("Загружаем все ключи параллельно...")
    
    all_keys = []
    with ThreadPoolExecutor(max_workers=len(urls)) as executor:
        futures = {executor.submit(fetch_keys, url): url for url in urls}
        for future in as_completed(futures):
            keys, url = future.result()
            print(f"Загружено {len(keys)} ключей из {url}")
            all_keys.extend([(key, url) for key in keys])
    
    print(f"Всего загружено {len(all_keys)} ключей")
    
    print("Проверяем все ключи одновременно...")
    working_keys = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_key, key_info): key_info for key_info in all_keys}
        completed = 0
        total = len(all_keys)
        start_time = time.time()
        
        for future in as_completed(futures):
            result = future.result()
            completed += 1
            if completed % 100 == 0:
                elapsed = time.time() - start_time
                speed = completed / elapsed if elapsed > 0 else 0
                print(f"Проверено {completed}/{total} ключей (скорость: {speed:.1f} ключей/сек)")
            if result:
                result["first_seen"] = old_first_seen.get(result["key"], now)
                working_keys.append(result)
    
    working_keys.sort(key=lambda x: x["latency_ms"])
    print(f"Найдено {len(working_keys)} рабочих ключей")
    
    country_stats = defaultdict(int)
    for key_data in working_keys:
        country_name, _ = get_country_and_flag_from_key(key_data["key"])
        country_stats[country_name] += 1
    
    print("\nСтатистика по странам:")
    for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True)[:MAX_COUNTRIES]:
        print(f"  {country}: {count} ключей")
    
    results = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total_working": len(working_keys),
        "all_keys": working_keys
    }
    
    os.makedirs("docs", exist_ok=True)
    with open("docs/keys.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("Сохранено в docs/keys.json")
    
    top50 = working_keys[:50]
    
    save_keys_with_locations(top50, "docs/main_keys.txt", add_header=True)
    save_keys_with_locations(working_keys, "docs/keys.txt", add_header=False)
    
    with open("docs/top_50.txt", "w", encoding="utf-8") as f:
        for i, key_data in enumerate(top50, 1):
            country_name, flag = get_country_and_flag_from_key(key_data["key"])
            source_type = "BLACK" if key_data["is_black"] else "WHITE"
            protocol = key_data["key"].split("://")[0] if "://" in key_data["key"] else "unknown"
            f.write(f"#{i} Ping: {key_data['latency_ms']}ms | {flag} {country_name} | {protocol} | {source_type}\n")
            f.write(f"{key_data['key']}\n\n")
    print(f"Сохранено {len(top50)} ключей в docs/top_50.txt")
    
    total_time = time.time() - start_time
    print(f"\n✅ Готово! Время выполнения: {total_time:.1f} секунд")

if __name__ == "__main__":
    main()
