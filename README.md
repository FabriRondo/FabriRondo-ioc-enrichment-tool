### IOC Enrichment Tool

Script en Python que consulta un indicador de compromiso (IOC) — hash de archivo, IP, dominio o URL — contra dos fuentes de threat intelligence (VirusTotal y AlienVault OTX) y devuelve un veredicto combinado. Guarda un historial de todas las consultas realizadas en `resultados.json`.

## Por qué

Cuando un analista SOC investiga un indicador sospechoso, suele tener que revisarlo manualmente en varias plataformas. Esta herramienta automatiza esa consulta cruzada, ahorrando tiempo y dejando registro de lo investigado.

## Cómo funciona

1. Detecta automáticamente el tipo de IOC que se le pasa (hash / IP / dominio / URL).
2. Consulta VirusTotal para ver cuántos motores antivirus lo marcan como malicioso sobre el total analizado, clasificando el resultado en **LIMPIO / SOSPECHOSO / MALICIOSO**.
3. Consulta AlienVault OTX para ver cuántos reportes de la comunidad existen sobre ese indicador.
4. Muestra ambos veredictos y guarda el resultado en un historial local.

## Requisitos

- Python 3.10+
- Librería `requests`
- API key gratuita de [VirusTotal](https://www.virustotal.com/gui/join-us)
- API key gratuita de [AlienVault OTX](https://otx.alienvault.com/)

## Instalación

```bash
git clone https://github.com/FabriRondo/ioc-enrichment-tool.git
cd ioc-enrichment-tool
pip install requests
```

Configurar las API keys como variables de entorno:

```bash
echo 'export VT_API_KEY="tu_key_de_virustotal"' >> ~/.bashrc
echo 'export OTX_API_KEY="tu_key_de_otx"' >> ~/.bashrc
source ~/.bashrc
```

## Uso

```bash
python3 ioc_check.py <hash|ip|dominio|url>
```

Ejemplos:

```bash
python3 ioc_check.py 8.8.8.8
python3 ioc_check.py google.com
python3 ioc_check.py 44d88612fea8a8f36de82e1278abb02f
```

(el último es el hash del archivo de test **EICAR**, un estándar de la industria diseñado para que cualquier antivirus lo detecte — útil para probar la herramienta sin necesidad de malware real).

## Salida

```
VirusTotal: MALICIOSO (64/74 engines)
AlienVault OTX: 50 reporte(s) de la comunidad
```

El número de motores ("engines") varía según el IOC: VirusTotal agrega y quita partners con el tiempo, y no todos los motores analizan todos los tipos de indicador (los de reputación de IP/dominio no son los mismos que los de análisis de archivos).

Cada consulta también queda registrada en `resultados.json` con fecha, IOC, tipo detectado y ambos veredictos.

## Limitaciones

- El veredicto de OTX se basa en cantidad de reportes de la comunidad (`pulse_info.count`), no en un análisis antivirus directo — complementa a VirusTotal pero mide algo distinto.
- Sujeto a los límites de cuota gratuita de ambas APIs (VirusTotal: 4 consultas/min; OTX: sin límite estricto documentado, pero de uso razonable).

## Próximas mejoras

- Exportar historial a CSV.
- Aceptar múltiples IOCs desde un archivo de entrada.
