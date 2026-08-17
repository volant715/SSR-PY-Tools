import socket
import urllib.request
import urllib.error
import time
import math
import platform
import hashlib
from datetime import datetime

def clear_screen():
    print("\n" + "="*70 + "\n")

def print_banner():
    print(r"""
   _____ _____ _____   _______          _       
  / ____/ ____|  __ \ |__   __|        | |      
 | (___| (___ | |__) |   | | ___   ___ | |___   
  \___ \\___ \|  _  /    | |/ _ \ / _ \| / __|  
  ____) |___) | | \ \    | | (_) | (_) | \__ \  
 |_____/_____/|_|  \_\   |_|\___/ \___/|_|___/  
    [ Service Server Reports & Security Tools v3.0 ]
    """)

def save_report(tool_name, data):
    """Guarda automáticamente un registro en el historial de reportes."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_entry = f"[{timestamp}] Tool: {tool_name}\n{data}\n" + "-"*50 + "\n"
    try:
        with open("reportes_ssr.txt", "a", encoding="utf-8") as f:
            f.write(report_entry)
        print("\n[💾] Reporte guardado exitosamente en 'reportes_ssr.txt'")
    except Exception as e:
        print(f"\n[⚠️] No se pudo guardar el reporte: {e}")

# ==========================================
# 1. ESCÁNER DE PUERTOS Y LATENCIA
# ==========================================
def tool_port_scanner():
    clear_screen()
    print("--- [ 1. ESCÁNER DE PUERTOS Y LATENCIA ] ---")
    target = input("Introduce la IP o dominio objetivo (ej. 127.0.0.1): ").strip()
    if not target:
        target = "127.0.0.1"
    
    ports_input = input("Introduce puertos separados por coma (ej. 21,22,80,443,3306) o Enter para predeterminados: ").strip()
    if ports_input:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except ValueError:
            print("❌ Formato de puertos inválido. Usando puertos predeterminados.")
            ports = [21, 22, 80, 443, 3306, 8080]
    else:
        ports = [21, 22, 80, 443, 3306, 8080]

    print(f"\n[🔍] Escaneando {target}...")
    print("-" * 55)
    print(f"{'PUERTO':<10} | {'ESTADO':<15} | {'LATENCIA':<15}")
    print("-" * 55)

    report_results = f"Objetivo: {target}\n"
    for port in ports:
        start_time = time.time()
        status = "CERRADO"
        latency = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                result = s.connect_ex((target, port))
                latency = round((time.time() - start_time) * 1000, 2)
                if result == 0:
                    status = "ABIERTO"
        except socket.error:
            pass
        
        status_str = f"🟢 {status}" if status == "ABIERTO" else f"🔴 {status}"
        latency_str = f"{latency} ms" if latency is not None else "-"
        print(f"{port:<10} | {status_str:<15} | {latency_str:<15}")
        report_results += f"Puerto {port}: {status} ({latency_str})\n"
    
    print("-" * 55)
    save_report("Port Scanner", report_results)
    input("\nPresiona Enter para volver al menú principal...")

# ==========================================
# 2. ESTADO Y LATENCIA DE DOMINIO / URL
# ==========================================
def tool_domain_status():
    clear_screen()
    print("--- [ 2. ESTADO Y LATENCIA DE DOMINIO / URL ] ---")
    url = input("Introduce la URL completa (ej. https://example.com): ").strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[🌐] Consultando {url}...")
    start_time = time.time()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            latency = round((time.time() - start_time) * 1000, 2)
            msg = (f"URL: {url}\nEstado HTTP: {response.status} {response.reason}\n"
                   f"Latencia: {latency} ms\nServidor: {response.headers.get('Server', 'No especificado')}")
            print(f"\n✅ Estado HTTP: {response.status} {response.reason}")
            print(f"⏱️ Tiempo de Respuesta: {latency} ms")
            print(f"📦 Servidor: {response.headers.get('Server', 'No especificado')}")
            save_report("Domain Status", msg)
    except urllib.error.HTTPError as e:
        latency = round((time.time() - start_time) * 1000, 2)
        msg = f"URL: {url}\nError HTTP: {e.code} {e.reason}\nLatencia: {latency} ms"
        print(f"\n⚠️ El servidor respondió con error HTTP: {e.code} {e.reason}")
        print(f"⏱️ Tiempo de Respuesta: {latency} ms")
        save_report("Domain Status", msg)
    except Exception as e:
        print(f"\n❌ Error al conectar con el dominio: {e}")

    input("\nPresiona Enter para volver al menú principal...")

# ==========================================
# 3. AUDITOR DE CABECERAS DE SEGURIDAD
# ==========================================
def tool_security_headers():
    clear_screen()
    print("--- [ 3. AUDITOR DE CABECERAS DE SEGURIDAD HTTP ] ---")
    url = input("Introduce la URL a auditar (ej. https://example.com): ").strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy"
    ]

    print(f"\n[🛡️] Analizando cabeceras en {url}...\n")
    report_data = f"URL Auditada: {url}\nCabeceras:\n"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SSR-Security-Auditor'})
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = response.headers
            for header in security_headers:
                val = headers.get(header)
                if val:
                    print(f"🟢 [PRESENTE] {header}: {val[:50]}...")
                    report_data += f"  [+] {header}: Presente\n"
                else:
                    print(f"🔴 [FALTRANTE] {header} no está configurada.")
                    report_data += f"  [-] {header}: Faltante\n"
        save_report("Security Headers", report_data)
    except Exception as e:
        print(f"❌ Error al realizar la auditoría: {e}")

    input("\nPresiona Enter para volver al menú principal...")

# ==========================================
# 4. EVALUADOR DE FORTALEZA DE CONTRASEÑAS
# ==========================================
def tool_password_auditor():
    clear_screen()
    print("--- [ 4. EVALUADOR DE FORTALEZA Y ENTROPÍA ] ---")
    password = input("Introduce la contraseña a evaluar: ")
    
    if not password:
        print("❌ Contraseña vacía.")
        input("\nPresiona Enter para continuar...")
        return

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32

    entropy = length * math.log2(pool_size) if pool_size > 0 else 0

    if entropy < 28:
        strength = "MUY DÉBIL"
    elif entropy < 36:
        strength = "DÉBIL"
    elif entropy < 60:
        strength = "MODERADA"
    elif entropy < 80:
        strength = "FUERTE"
    else:
        strength = "MUY FUERTE"

    print("\n" + "-"*40)
    print(f"📏 Longitud: {length} caracteres")
    print(f"🔐 Entropía estimada: {round(entropy, 2)} bits")
    print(f"⭐ Calificación: {strength}")
    print("-" * 40)

    save_report("Password Auditor", f"Longitud: {length} | Entropía: {round(entropy, 2)} bits | Calificación: {strength}")
    input("\nPresiona Enter para volver al menú principal...")

# ==========================================
# 5. INFORMACIÓN DE RED LOCAL Y SISTEMA
# ==========================================
def tool_network_info():
    clear_screen()
    print("--- [ 5. INFORMACIÓN DE RED LOCAL Y SISTEMA ] ---")
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.error:
        local_ip = "No disponible"

    info = (f"Hostname: {hostname}\nIP Local: {local_ip}\n"
            f"OS: {platform.system()} {platform.release()} ({platform.machine()})\n"
            f"Python: {platform.python_version()}")

    print(f"💻 Nombre de Host: {hostname}")
    print(f"🏠 IP Local: {local_ip}")
    print(f"🖥️ Sistema Operativo: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"🐍 Versión de Python: {platform.python_version()}")
    
    save_report("Network & System Info", info)
    input("\nPresiona Enter para volver al menú principal...")

# ==========================================
# 6. VERIFICADOR DE PROPAGACIÓN DNS
# ==========================================
def tool_dns_lookup():
    clear_screen()
    print("--- [ 6. VERIFICADOR DE PROPAGACIÓN DNS ] ---")
    domain = input("Introduce el dominio (ej. google.com): ").strip()
    if not domain:
        print("❌ Dominio inválido.")
        input("\nPresiona Enter...")
        return
    
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n✅ Dirección IP principal para '{domain}': {ip}")
        save_report("DNS Lookup", f"Dominio: {domain} -> IP: {ip}")
    except socket.gaierror:
        print(f"\n❌ No se pudo resolver el dominio '{domain}'. Comprueba tu conexión o el nombre.")
    
    input("\nPresiona Enter para volver al menú principal...")

# ==========================================
# 7. ANALIZADOR DE ESTABILIDAD (TCP PING)
# ==========================================
def tool_tcp_ping():
    clear_screen()
    print("--- [ 7. ANALIZADOR DE ESTABILIDAD (TCP PING) ] ---")
    target = input("Introduce la IP o dominio objetivo: ").strip()
    port_input = input("Puerto a probar (por defecto 80 o 443): ").strip()
    port = int(port_input) if port_input.isdigit() else 80

    print(f"\n[⏱️] Enviando 5 sondas TCP a {target}:{port}...")
    times = []
    for i in range(1, 6):
        start = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                if s.connect_ex((target, port)) == 0:
                    latency = (time.time() - start) * 1000
                    times.append(latency)
                    print(f"  Prode #{i}: Conectado en {round(latency, 2)} ms")
                else:
                    print(f"  Prode #{i}: Timeout / Cerrado")
        except:
            print(f"  Prode #{i}: Error de conexión")
        time.sleep(0.4)

    if times:
        avg = sum(times) / len(times)
        result_msg = f"Target: {target}:{port} | Exitosos: {len(times)}/5 | Promedio: {round(avg, 2)} ms"
        print(f"\n✅ Promedio de latencia: {round(avg, 2)} ms. Éxito: {len(times)}/5")
        save_report("TCP Ping", result_msg)
    else:
        print("\n❌ Host inalcanzable o puerto cerrado en todas las pruebas.")

    input("\nPresiona Enter para volver al menú principal...")

# ==========================================
# 8. AUDITOR DE INTEGRIDAD DE ARCHIVOS (HASHER)
# ==========================================
def tool_file_hasher():
    clear_screen()
    print("--- [ 8. GENERADOR DE HASH SHA-256 (INTEGRIDAD) ] ---")
    path = input("Introduce la ruta absoluta o relativa del archivo: ").strip().strip('"')
    
    try:
        with open(path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            print(f"\n🔑 Hash SHA-256:\n{file_hash}")
            save_report("File Hasher", f"Archivo: {path} | SHA-256: {file_hash}")
    except FileNotFoundError:
        print("\n❌ Error: Archivo no encontrado. Verifica la ruta.")
    except Exception as e:
        print(f"\n❌ Error al leer el archivo: {e}")

    input("\nPresiona Enter para volver al menú principal...")

# ==========================================
# MENÚ PRINCIPAL
# ==========================================
def main():
    while True:
        clear_screen()
        print_banner()
        print("Selecciona una herramienta del sistema:")
        print("  1. 🔍 Escáner de Puertos y Latencia")
        print("  2. 🌐 Estado y Latencia de Dominios / URL")
        print("  3. 🛡️ Auditor de Cabeceras de Seguridad HTTP")
        print("  4. 🔐 Evaluador de Fortaleza de Contraseñas")
        print("  5. 💻 Información de Red Local y Sistema")
        print("  6. 📡 Verificador de Propagación DNS")
        print("  7. ⏱️ Analizador de Estabilidad (TCP Ping)")
        print("  8. 📁 Generador de Hash SHA-256 (Integridad)")
        print("  9. ❌ Salir")
        
        choice = input("\nIntroduce una opción (1-9): ").strip()
        
        if choice == '1':
            tool_port_scanner()
        elif choice == '2':
            tool_domain_status()
        elif choice == '3':
            tool_security_headers()
        elif choice == '4':
            tool_password_auditor()
        elif choice == '5':
            tool_network_info()
        elif choice == '6':
            tool_dns_lookup()
        elif choice == '7':
            tool_tcp_ping()
        elif choice == '8':
            tool_file_hasher()
        elif choice == '9':
            print("\n¡Gracias por usar SSR Tools! Hasta pronto.\n")
            break
        else:
            print("\n❌ Opción no válida. Por favor, selecciona entre 1 y 9.")
            time.sleep(1.5)

if __name__ == "__main__":
    main()