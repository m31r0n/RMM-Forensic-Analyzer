# RMM Forensic Analyzer v3.0 — DFIR Edition

> Herramienta DFIR para analisis forense profundo de logs de herramientas RMM.
> Soporta **AnyDesk, TeamViewer, ScreenConnect, Chrome Remote Desktop, Splashtop y RustDesk**.
> Genera informes HTML con graficos, XLSX multi-hoja y CSVs listos para incluir en informes periciales.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://github.com/m31r0n/RMM-Forensic-Analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/m31r0n/RMM-Forensic-Analyzer/actions)

---

## Herramientas RMM soportadas

| RMM | Archivos que parsea |
|---|---|
| **AnyDesk** | `ad.trace`, `ad_svc.trace`, `connection_trace.txt` (UTF-16 LE) |
| **TeamViewer** | `Connections_incoming.txt`, `Connections.txt`, `TeamViewer*_Logfile.log` |
| **ScreenConnect** | Logs de sesion (texto), `SessionOutput.db` (SQLite) |
| **Chrome Remote Desktop** | Logs JSON de CRD |
| **Splashtop** | `log_*.log` |
| **RustDesk** | Logs de texto de RustDesk |

---

## Funcionalidades principales

- **Descubrimiento automatico de logs** — escanea directorios, ZIPs y salidas de KAPE
- **Deteccion por contenido** — identifica logs por firma interna, no solo por nombre
- **Analisis multi-host** — infiere hostname desde estructura de carpetas KAPE
- **Scoring de riesgo** — reglas comunes + reglas especificas por RMM (CRITICO/ALTO/MEDIO/BAJO)
- **Correlacion cross-RMM** — detecta IPs que aparecen en multiples herramientas
- **Contexto de incidente** — proximidad temporal (±24h/3d/7d) y clasificacion por pais
- **Enriquecimiento de IPs** — AbuseIPDB, VirusTotal, CriminalIP, nodos TOR
- **3 formatos de salida** — HTML (Chart.js), XLSX (8 hojas), CSVs

### Scoring de riesgo

Cada sesion recibe un nivel basado en indicadores forenses:

| Factor | Puntos | Aplica a |
|---|---|---|
| Portapapeles masivo > 100 archivos | +4 | AnyDesk |
| Transferencia de archivo aceptada | +3 | Todos |
| Elevacion de privilegios | +3 | Todos |
| >= 5 cambios a Winlogon | +3 | AnyDesk |
| Portapapeles elevado > 20 archivos | +2 | AnyDesk |
| Comandos ejecutados remotamente | +2 | ScreenConnect |
| Acceso desatendido | +2 | TeamViewer |
| Relay de texto | +1 | AnyDesk |
| Sesion minimizada | +1 | AnyDesk |
| Sin contrasena (hasPw: N) | +1 | AnyDesk |
| Tunel TCP activo | +1 | AnyDesk |

---

## Instalacion

```bash
git clone https://github.com/m31r0n/RMM-Forensic-Analyzer.git
cd RMM-Forensic-Analyzer

# Opcion A — instalar dependencias directamente
pip install -r requirements.txt

# Opcion B — instalar como paquete (habilita los comandos rmm-forensic y anydesk-forensic)
pip install -e .
```

**Dependencias:**
- `openpyxl` — generacion XLSX
- `requests` — consultas API (enriquecimiento de IPs)
- `colorama` — colores en consola
- `rich` — progress bars y paneles (fallback a colorama si no esta)

---

## Uso

### Menu interactivo
```bash
python -m rmm_forensic
# o si instalado con pip:
rmm-forensic
```

### CLI directo
```bash
# Analisis de directorio completo (descubre todos los RMMs)
rmm-forensic --input /ruta/al/caso

# Solo AnyDesk y TeamViewer
rmm-forensic --input /caso --rmm anydesk,teamviewer

# Con fecha de incidente y pais de origen
rmm-forensic --input /caso --incident-date 2024-03-15 --country MX

# Con enriquecimiento de IPs
rmm-forensic --input /caso --vt-key TU_KEY --abuse-key TU_KEY --criminalip-key TU_KEY

# Solo resumen en consola, sin generar archivos
rmm-forensic --input /caso --summary --no-html --no-xlsx --no-csv

# Legacy (deprecado): archivos AnyDesk individuales
rmm-forensic --trace ad.trace --conn connection_trace.txt
```

### Flags disponibles

| Flag | Descripcion |
|---|---|
| `--input PATH` | Directorio, ZIP o archivo de entrada |
| `--rmm LIST` | Filtrar RMMs (separados por coma) |
| `--incident-date DATE` | Fecha del incidente (YYYY-MM-DD) |
| `--country CC` | Codigo ISO del pais de origen |
| `--hostname NAME` | Filtrar por hostname |
| `--user USERNAME` | Filtrar por usuario |
| `--no-api` | No consultar APIs de enriquecimiento |
| `--vt-key KEY` | VirusTotal API key |
| `--abuse-key KEY` | AbuseIPDB API key |
| `--criminalip-key KEY` | CriminalIP API key |
| `--output DIR` | Directorio de salida |
| `--summary` | Mostrar resumen en consola |
| `--no-html` | No generar HTML |
| `--no-xlsx` | No generar XLSX |
| `--no-csv` | No generar CSVs |

---

## Configuracion de API keys

Las API keys se guardan en `config.json` (excluido de Git por `.gitignore`).

### Opcion 1 — Menu interactivo
Opcion `[3] Configurar API keys` del menu principal.

### Opcion 2 — Archivo de configuracion
```bash
cp config.example.json config.json
# Edita config.json con tus API keys
```

### Opcion 3 — Variables de entorno
```bash
export VT_API_KEY="tu_key"
export ABUSEIPDB_API_KEY="tu_key"
export CRIMINALIP_API_KEY="tu_key"
rmm-forensic --input /caso
```

**Prioridad:** variables de entorno > config.json > valores por defecto

> `config.json` esta en `.gitignore` — nunca se subira a GitHub.

---

## Estructura del proyecto

```
RMM-Forensic-Analyzer/
├── rmm_forensic/
│   ├── __init__.py
│   ├── __main__.py              # CLI + menu interactivo
│   ├── config.py                # Gestion de configuracion
│   ├── utils.py                 # Utilidades compartidas
│   ├── models/
│   │   ├── base.py              # RMMType, RMMSession, RMMConnection, ParseResult
│   │   ├── enrichment.py        # IPEnrichment (AbuseIPDB, VT, CriminalIP, TOR)
│   │   ├── incident.py          # IncidentContext (fecha, pais, ventanas temporales)
│   │   └── summary.py           # ForensicSummary (cross-RMM, correlacion)
│   ├── parsers/
│   │   ├── base.py              # BaseParser ABC
│   │   ├── registry.py          # ParserRegistry (auto-registro)
│   │   ├── anydesk/             # ad.trace, connection_trace.txt
│   │   ├── teamviewer/          # Connections_incoming, Logfile
│   │   ├── screenconnect/       # Session logs, SessionOutput.db
│   │   ├── chrome_remote_desktop/
│   │   ├── splashtop/
│   │   └── rustdesk/
│   ├── discovery/
│   │   ├── engine.py            # LogDiscoveryEngine (dirs, ZIPs, KAPE)
│   │   ├── known_paths.py       # Rutas conocidas por OS y RMM
│   │   ├── signatures.py        # Firmas de contenido para deteccion
│   │   ├── kape.py              # Mapeo de salida KAPE
│   │   └── archive.py           # Extraccion de ZIPs
│   ├── analyzer/
│   │   ├── risk_scoring.py      # Scoring de riesgo (comun + por RMM)
│   │   ├── correlator.py        # Correlacion cross-RMM
│   │   ├── incident.py          # Proximidad temporal al incidente
│   │   └── country.py           # Clasificacion por pais
│   ├── apis/
│   │   ├── cache.py             # Cache JSON con TTL
│   │   ├── virustotal.py        # VirusTotal v3
│   │   ├── abuseipdb.py         # AbuseIPDB v2
│   │   ├── criminalip.py        # CriminalIP
│   │   ├── tor_exit_nodes.py    # Lista de nodos de salida TOR
│   │   └── enrichment.py        # Orquestador de enriquecimiento
│   └── reports/
│       ├── common.py            # Badges HTML, colores por RMM
│       ├── html_report.py       # Informe HTML + graficos Chart.js
│       ├── xlsx_report.py       # XLSX 8 hojas con formato condicional
│       └── csv_report.py        # 6 CSVs (incluye cross_rmm_correlation)
├── tests/
│   └── test_parsers.py          # 40 tests (pytest)
├── config.example.json          # Plantilla de configuracion (sin claves)
├── requirements.txt
├── pyproject.toml
└── .gitignore
```

---

## Ubicaciones de archivos por RMM

### AnyDesk (Windows)
| Archivo | Ruta |
|---|---|
| `ad.trace` | `%AppData%\AnyDesk\ad.trace` |
| `ad_svc.trace` | `%ProgramData%\AnyDesk\ad_svc.trace` |
| `connection_trace.txt` | `%AppData%\AnyDesk\connection_trace.txt` |

### TeamViewer (Windows)
| Archivo | Ruta |
|---|---|
| `Connections_incoming.txt` | `%AppData%\TeamViewer\Connections_incoming.txt` |
| `Connections.txt` | `%AppData%\TeamViewer\Connections.txt` |
| `TeamViewer*_Logfile.log` | `%AppData%\TeamViewer\` |

### ScreenConnect (Windows)
| Archivo | Ruta |
|---|---|
| Session logs | `%ProgramFiles(x86)%\ScreenConnect\App_Data\Session.db` |
| `SessionOutput.db` | Directorio de datos de ScreenConnect |

---

## Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Licencia

MIT — libre para uso en investigaciones forenses, auditorias y respuesta a incidentes.
