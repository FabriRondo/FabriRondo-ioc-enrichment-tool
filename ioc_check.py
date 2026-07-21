import os
import sys
import requests
import base64
import json
from datetime import datetime

def detectar_tipo_ioc(ioc):
    if ioc.startswith("http"):
        return "url"
    elif ioc.replace(".", "").isdigit():
        return "ip"
    elif "." in ioc:
        return "dominio"
    else:
        return "hash"

def consultar_virustotal(ioc, tipo, api_key):
    if tipo == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif tipo == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif tipo == "dominio":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"

    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 404:
        print("IOC no encontrado en VirusTotal.")
        return None

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return stats
def consultar_alienvault(ioc, tipo, api_key):
    if tipo == "ip":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    elif tipo == "dominio":
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
    else:
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general"
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 404:
        print("IOC no encontrado en AlienVault.")
        return None

    data = response.json()
    cantidad_reportes = data["pulse_info"]["count"]
    return cantidad_reportes

def leer_api_key(nombre_variable):
    api_key = os.environ.get(nombre_variable)
    if api_key is None:
        print(f"Error, la variable {nombre_variable} no existe")
        sys.exit()
    return api_key
def guardar_resultado(ioc, tipo, stats_vt, reportes_otx):
    if stats_vt is not None:
        detecciones_vt = stats_vt["malicious"]
    else:
        detecciones_vt = None

    registro = {
        "fecha": datetime.now().isoformat(),
        "ioc": ioc,
        "tipo": tipo,
        "virustotal_malicious": detecciones_vt,
        "otx_reportes": reportes_otx
    }

    try:
        with open("resultados.json", "r") as f:
            historial = json.load(f)
    except FileNotFoundError:
        historial = []

    historial.append(registro)

    with open("resultados.json", "w") as f:
        json.dump(historial, f, indent=2)

def main():
    vt_api_key = leer_api_key("VT_API_KEY")
    otx_api_key = leer_api_key("OTX_API_KEY")

    ioc = sys.argv[1]
    tipo = detectar_tipo_ioc(ioc)

    stats_vt = consultar_virustotal(ioc, tipo, vt_api_key)
    reportes_otx = consultar_alienvault(ioc, tipo, otx_api_key)
    guardar_resultado(ioc, tipo, stats_vt, reportes_otx)
    if stats_vt is not None:
        if stats_vt["malicious"] > 0:
            print("VirusTotal: Esto es malicioso")
        else:
            print("VirusTotal: Esto NO es malicioso.")

    if reportes_otx is not None:
        if reportes_otx > 0:
            print(f"AlienVault OTX: {reportes_otx} reporte(s) de la comunidad")
        else:
            print("AlienVault OTX: sin reportes de la comunidad")

if __name__ == "__main__":
    main()
