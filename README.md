<div align="center">

<br />
<img src="docs/baseline/logo2.png" alt="CIPHERTRACE AI" width="520" />
<br /><br />

**Detección Pasiva de Amenazas en Tráfico Cifrado con IA Híbrida, Algoritmo Genético, Explicabilidad (XAI) y Laboratorio AiTM**

[![Python 3.11](https://img.shields.io/badge/Python-3.11-5795F2?style=flat-square&labelColor=1C2226&logo=python&logoColor=F2F4F5)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-36C995?style=flat-square&labelColor=1C2226&logo=fastapi&logoColor=101416)](https://fastapi.tiangolo.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-CPU-F2A544?style=flat-square&labelColor=1C2226&logo=pytorch&logoColor=101416)](https://pytorch.org/)
[![React 18](https://img.shields.io/badge/React-18-79ABFF?style=flat-square&labelColor=1C2226&logo=react&logoColor=101416)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-5795F2?style=flat-square&labelColor=1C2226&logo=typescript&logoColor=F2F4F5)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4-5795F2?style=flat-square&labelColor=1C2226&logo=tailwindcss&logoColor=F2F4F5)](https://tailwindcss.com/)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-272F35?style=flat-square&labelColor=1C2226&logo=postgresql&logoColor=F2F4F5)](https://www.postgresql.org/)
[![Docker Compose](https://img.shields.io/badge/Docker_Compose-Ready-36C995?style=flat-square&labelColor=1C2226&logo=docker&logoColor=101416)](https://docs.docker.com/compose/)

</div>

---

## ¿Qué es CIPHERTRACE AI?

**CIPHERTRACE AI** es una plataforma SOC (*Security Operations Center*) de análisis pasivo diseñada para detectar amenazas avanzadas ocultas dentro de tráfico cifrado **sin descifrar jamás el payload** ni requerir inspección SSL/TLS invasiva (*TLS MITM*).

En lugar de romper el cifrado de las comunicaciones, el motor extrae **18 características pasivas observables** en red (temporización inter-paquete, distribución de tamaños, asimetría de bytes, cabeceras no cifradas `ClientHello`/`ServerHello`, entropía Shannon del SNI, tasa DNS/DoH, latencia de doble salto y redirecciones) para identificar 5 categorías de tráfico:

| Vector | Descripción | Señales pasivas clave |
| :--- | :--- | :--- |
| **`BENIGN`** | Tráfico HTTPS/TLS legítimo | SNI de baja entropía, latencia directa, 0 redirecciones |
| **`C2_BEACONING`** | *Command & Control* periódico | Desviación IAT muy baja, paquetes uniformes pequeños, pocos *cipher suites* |
| **`DOH_TUNNEL`** | Tunelización *DNS-over-HTTPS* | Alta entropía Shannon y longitud en SNI/subdominios, alta tasa DNS/DoH |
| **`EXFILTRATION`** | Exfiltración masiva de datos | Asimetría saliente marcada (`bytes_sent >> bytes_recv`), paquetes cercanos al MTU |
| **`PHISHING_AITM`** | Proxy inverso *Adversary-in-the-Middle* | Latencia de doble salto elevada (`>200 ms`), cadena de redirecciones TLS/HTTP |

---

## Arquitectura y Funcionamiento

```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#101416",
    "primaryColor": "#1C2226",
    "primaryTextColor": "#F2F4F5",
    "primaryBorderColor": "#343D43",
    "lineColor": "#5795F2",
    "secondaryColor": "#272F35",
    "tertiaryColor": "#151A1E",
    "fontFamily": "Inter, system-ui, sans-serif"
  }
}}%%
flowchart LR
    A["Fuentes de Tráfico<br/>(Captura en vivo / PCAP / CSV / Simulador / Proxy AiTM)"] --> B["Extractor Pasivo<br/>(Scapy + Pandas · 18 Atributos)"]
    B --> C["Selección Genética<br/>(Máscara AG: 18 → 8 Atributos)"]
    C --> D["Motor Híbrido ML/DL<br/>MLP + PyTorch Autoencoder<br/>+ Random Forest + Isolation Forest"]
    D --> E["Explicabilidad (XAI)<br/>z-score vs Línea Base Benigna"]
    E --> F["PostgreSQL / SQLite<br/>+ WebSocket /ws/alerts"]
    F --> G["Consola SOC · Dark Bento Grid<br/>(React + Recharts + Tailwind)"]

    classDef surface fill:#1C2226,stroke:#343D43,stroke-width:1.5px,color:#F2F4F5
    classDef accent fill:#1C2226,stroke:#5795F2,stroke-width:1.5px,color:#F2F4F5
    classDef success fill:#1C2226,stroke:#36C995,stroke-width:1.5px,color:#F2F4F5
    classDef secondary fill:#272F35,stroke:#343D43,stroke-width:1.5px,color:#F2F4F5

    class A,F secondary
    class B,E surface
    class C,D accent
    class G success
```

### Motor IA & Optimización con Algoritmo Genético

1. **Fase 1 del Algoritmo Genético (Selección de Atributos):** reduce los **18 atributos pasivos** iniciales a **8 características óptimas** (**55.6% menos dimensionalidad**):
   - `duration_ms` · `byte_asymmetry_ratio` · `packets_recv` · `iat_std_ms` · `pkt_size_mean` · `cipher_suite_count` · `dns_query_rate` · `double_hop_latency_ms`
2. **Fase 2 del Algoritmo Genético (Pesos del Ensamble Híbrido):** combina la probabilidad supervisada de la red **MLP** (amenazas conocidas) con el error de reconstrucción del **PyTorch Autoencoder** entrenado únicamente con tráfico benigno (detección *Zero-Day*). Los pesos y el umbral se optimizan genéticamente y se persisten en `backend/artifacts/ga_config.json`:
   ```text
   risk_score = 0.8323 * P(MLP) + 0.1677 * Anomaly(Autoencoder)      |      Umbral ALTO >= 0.4367
   ```
3. **Explicabilidad (XAI):** calcula los 3 atributos con mayor desviación (`|z-score|`) respecto al perfil benigno basal y genera explicaciones claras en español para el analista SOC.

### Rendimiento Validado (Validación Cruzada Estratificada `k = 5`, 20,000 flujos)

Métricas binarias benigno/malicioso sobre el dataset mixto **17,500 flujos públicos + 2,500 de laboratorio** (ver procedencia más abajo):

| Modelo | Paradigma | Precisión | Recall | F1-Score | Latencia Media |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Random Forest** | Supervisado Multiclase | 97.86% | 98.70% | 98.28% | 0.0111 ms |
| **Red Neuronal MLP** | Deep Learning Supervisado | 93.93% | 95.40% | 94.66% | 0.0009 ms |
| **PyTorch Autoencoder** | No Supervisado (*Zero-Day*) | 86.12% | 30.66% | 45.22% | 0.0002 ms |
| **Isolation Forest** | Anomalía No Supervisada | 85.25% | 28.73% | 42.98% | 0.0086 ms |
| **Ensamble Híbrido (AG)** | **MLP + Autoencoder Ponderado** | **93.84%** | **95.50%** | **94.66%** | **0.0011 ms** |

> Matriz de confusión del ensamble híbrido sobre 20,000 flujos: `TN = 9,373`, `FP = 627`, `FN = 450`, `TP = 9,550`.
> El Autoencoder e Isolation Forest se entrenan solo con tráfico benigno y se evalúan como detectores de anomalía; su recall es bajo porque no conocen las clases de ataque. El ensamble híbrido los pondera con el MLP para la detección *zero-day*.


---

## Las 4 Vistas de la Consola SOC

1. **Live SOC Overview:** incluye el panel **Sensor Híbrido (Captura Pasiva En Vivo / Offline)** para iniciar o detener la captura pasiva en tiempo real sobre interfaces de red (`scapy.sniff`), KPIs en vivo (*Flujos Analizados*, *Alertas Activas*, *Latencia Media*, *Tasa de Anomalía*), gráfica temporal de `risk_score`, distribución por vector de amenaza y tabla filtrable (`TODOS`, `ALTO`, `MEDIO`, `BAJO`) con **Drawer XAI** interactivo.
2. **Laboratorio AiTM & Inyección:** inyección controlada de los 5 escenarios (`POST /api/lab/simulate`), portales locales comparativos (`Portal Legítimo` vs. `Proxy Inverso AiTM` con relay HTTP real e interceptación de cookie), guía paso a paso y feed WebSocket en tiempo real.
3. **Motor IA & Algoritmo Genético:** procedencia trazable del dataset (`backend/data/raw/` vs. respaldo estadístico), curvas de convergencia generacional del AG (Fase 1 y Fase 2), mapa visual de atributos seleccionados/descartados, pesos óptimos, matriz de confusión y comparativa `k=5`.
4. **Inspector Pasivo PCAP / CSV (Modo Offline):** carga *Drag & Drop* de archivos `.pcap`, `.pcapng` y `.csv` hacia `POST /api/analyze/file` con desglose de detecciones flujo por flujo.

---

## Cómo Utilizarlo

### Opción 1: Docker Compose (Recomendada — 1 comando)

Requisitos: **Docker** y **Docker Compose**.

```bash
git clone https://github.com/JoelFlC/CIPHERTRACE-AI.git
cd CIPHERTRACE-AI
docker compose up -d --build
```

Esto levanta automáticamente 3 contenedores conectados en la red `ciphertrace-net` con puertos estándar (`8000` y `5173`):
- **`ciphertrace-db`**: PostgreSQL 16 (`ciphertrace_db`) con persistencia en el volumen `pgdata` y `healthcheck`. Se publica en `127.0.0.1:5434` (no en `5433`) para no chocar con otras instancias locales de PostgreSQL; el backend lo consume internamente como `db:5432`.
- **`ciphertrace-backend`**: FastAPI + Uvicorn en `:8000` con capacidades `NET_RAW` / `NET_ADMIN` para captura pasiva en vivo, creación automática de tablas y montaje de `./backend/artifacts` y `./backend/data/raw`.
- **`ciphertrace-frontend`**: React + Nginx en `:5173`.

> **Si el backend queda en estado `Created` o no responde en `:8000`,** revisa `docker compose logs db`. La causa habitual es un conflicto de puerto en el host; cambia el mapeo `5434:5432` por otro libre y vuelve a ejecutar `docker compose up -d`.


#### Perfil Opcional en Linux (`host-capture`) para Capturar la Interfaz Física Real (`eth0` / `wlan0`)
Si deseas capturar directamente el tráfico de la tarjeta física de red de tu equipo Linux desde Docker:
```bash
docker compose --profile host-capture up -d --build db backend-host frontend
```

**Comandos útiles del día a día:**
```bash
docker compose up -d       # Encender los servicios sin reconstruir imágenes
docker compose ps          # Verificar estado de contenedores
docker compose logs -f     # Ver logs en tiempo real
docker compose stop        # Detener contenedores conservando los datos
docker compose down        # Detener y eliminar contenedores (mantiene pgdata)
```

---

### Opción 2: Ejecución Local sin Docker (SQLite Fallback)

Si `DATABASE_URL` no está definida, el backend usa automáticamente `sqlite:///./ciphertrace.db`.

**1. Backend (Python 3.11+ en puerto 8000)**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
> La captura en vivo fuera de Docker requiere `sudo` o la capability `CAP_NET_RAW` (por ejemplo `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)`). Sin privilegios, el resto de la plataforma funciona igual y `/api/capture/start` responde `403`.

**2. Frontend (Node.js 20+ en puerto 5173)**
```bash
cd frontend
npm install
npm run dev
```

---

## URLs Clave

| Recurso | URL | Propósito |
| :--- | :--- | :--- |
| **Consola SOC (Frontend)** | `http://localhost:5173` | Interfaz principal de monitorización y análisis |
| **Documentación API (Swagger)** | `http://localhost:8000/docs` | Explorador interactivo OpenAPI |
| **Estado del Sistema** | `http://localhost:8000/api/health` | Verificación de modelos cargados, pesos AG y WebSocket |
| **Portal Legítimo (Demo)** | `http://localhost:8000/lab/legit-portal` | Línea base de login TLS directo (~25 ms) |
| **Proxy Inverso AiTM (Demo)** | `http://localhost:8000/lab/aitm-proxy` | Relay HTTP local real (in-process) con captura de cookie de sesión ficticia |

---

## Endpoints Principales de la API

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Estado del motor híbrido y artefactos cargados |
| `GET` | `/api/dashboard/summary` | KPIs agregados del SOC y distribución de amenazas |
| `GET` | `/api/flows` | Flujos analizados y alertas recientes (`limit`, `risk_level`) |
| `GET` | `/api/ml/metrics` | Métricas `k=5` de modelos e historial de convergencia del AG |
| `POST` | `/api/lab/simulate` | Inyección controlada de tráfico (`BENIGN`, `C2_BEACONING`, `DOH_TUNNEL`, `EXFILTRATION`, `PHISHING_AITM`) |
| `POST` | `/api/analyze/file` | Análisis pasivo offline de capturas `.pcap`, `.pcapng` o `.csv` |
| `GET` | `/api/capture/interfaces` | Lista de interfaces y verificación de privilegios `CAP_NET_RAW` |
| `POST` | `/api/capture/start` | Inicia la captura pasiva en vivo por ventanas sin descifrar payload |
| `POST` | `/api/capture/stop` | Detiene la captura pasiva en vivo |
| `WS` | `/ws/alerts` | Stream WebSocket en tiempo real de flujos evaluados y alertas |

---

## Datasets Públicos, Muestras de Demo y Suite End-to-End

### Procedencia de los datos de entrenamiento

Los artefactos incluidos en `backend/artifacts/` se entrenaron con **20,000 flujos** (10,000 benignos + 2,500 por cada vector de ataque) compuestos por:

| Fuente | Flujos | Clases aportadas |
| :--- | ---: | :--- |
| `cicids2017_cleaned.csv` (CIC-IDS2017) | 7,620 | BENIGN, EXFILTRATION, C2_BEACONING |
| `BCCC-CIRA-CIC-DoHBrw-2020.csv` | 6,000 | BENIGN, DOH_TUNNEL |
| `5-Virut-20110815-2.binetflow.parquet` (CTU-13) | 3,880 | BENIGN, C2_BEACONING |
| Generador de laboratorio (`controlled_lab_generator`) | 2,500 | PHISHING_AITM |
| **Total** | **20,000** | 17,500 públicos + 2,500 de laboratorio |

> **Limitación declarada:** no existe un dataset público pasivo de phishing AiTM, por lo que `PHISHING_AITM` es 100% sintético. Los archivos crudos (`backend/data/raw/*.csv|*.parquet`) están en `.gitignore` por tamaño y **no se distribuyen con el repositorio**; los artefactos ya entrenados sí están versionados. La procedencia exacta queda registrada en `backend/artifacts/model_metrics.json` (`dataset.source_breakdown`).

Para reentrenar con datasets públicos reales, coloca los `.csv`/`.parquet` en `backend/data/raw/` y ejecuta:

```bash
backend/.venv/bin/python backend/scripts/prepare_public_datasets.py --train
```
*(Si `backend/data/raw/` está vacía o faltan clases como `PHISHING_AITM`, el pipeline usa respaldo estadístico/de laboratorio y registra la procedencia exacta en `model_metrics.json`.)*

### Limitaciones conocidas

- **Captura en vivo:** requiere privilegios `CAP_NET_RAW`/root. En Docker se resuelve con `cap_add`; el perfil `host-capture` permite ver la interfaz física (`eth0`/`wlan0`) en Linux.
- **Laboratorio AiTM:** el relay es HTTP local (ASGI, sin TLS ni dominio real) y las credenciales/cookies son ficticias. No se realiza MITM TLS ni se contactan servicios de terceros.
- **Alcance:** prototipo experimental; no está dimensionado para enlaces de decenas de Gbps ni para bloqueo automático en línea.

El proyecto incluye un generador de capturas reales (`.csv` y `.pcap` construido con Scapy) en `demo_samples/` y pruebas End-to-End automatizadas:

```bash
# Generar demo_samples/mixed_traffic_demo.csv (40 flujos) y sample_capture.pcap (5 flujos)
backend/.venv/bin/python backend/scripts/generate_demo_files.py

# Ejecutar la suite completa End-to-End (8/8 validaciones)
backend/.venv/bin/python backend/tests/test_e2e.py
```

---

## Guion de Demostración (3 Minutos)

1. **0:00 – 0:45 · Live SOC Overview (`http://localhost:5173`):** muestra el estado **LIVE** del WebSocket, el indicador **Análisis Pasivo (Sin Descifrado)** y las gráficas en vivo.
2. **0:45 – 1:45 · Detección AiTM en Vivo:** entra a **Laboratorio AiTM**, abre el **Proxy Inverso AiTM (Demo)** en otra pestaña y envía el formulario con las credenciales ficticias precargadas. Regresa a la consola SOC para ver la alerta `PHISHING_AITM` en tiempo real y abre su **Drawer XAI** (`double_hop_latency_ms`, `redirect_count`, `sni_length`).
3. **1:45 – 2:30 · Motor IA & Algoritmo Genético:** enseña cómo el AG redujo de 18 a 8 atributos optimizando el F1-Score del ensamble hasta **94.66%** sobre datos públicos + laboratorio.
4. **2:30 – 3:00 · Inspector PCAP / CSV:** arrastra `demo_samples/sample_capture.pcap` o `demo_samples/mixed_traffic_demo.csv` para demostrar la extracción pasiva y clasificación flujo por flujo.

---

## Estructura del Proyecto

```text
CIPHERTRACE-AI/
├── backend/
│   ├── app/
│   │   ├── api/            # Endpoints REST y WebSocket (/api, /ws/alerts)
│   │   ├── core/           # Esquema de 18 atributos pasivos y rutas de artefactos
│   │   ├── db/             # Configuración SQLAlchemy (PostgreSQL + SQLite fallback) y modelos
│   │   ├── lab/            # Portales locales controlados (/lab/legit-portal, /lab/aitm-proxy)
│   │   ├── ml/             # Dataset builder, Autoencoder PyTorch, Algoritmo Genético, extractor PCAP
│   │   ├── services/       # Motor de inferencia XAI, sniffer en vivo, simulador y WebSocket
│   │   └── main.py         # Punto de entrada FastAPI
│   ├── artifacts/          # Modelos entrenados (.joblib, .pt), ga_config.json y model_metrics.json
│   ├── data/processed/     # Dataset procesado de 20,000 flujos (público + laboratorio)
│   ├── data/raw/           # CSVs/Parquet públicos (no versionados por tamaño)
│   ├── scripts/            # generate_demo_files.py, prepare_public_datasets.py
│   ├── tests/              # Suite End-to-End (test_e2e.py)
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── assets/         # Identidad visual (logo.png)
│   │   ├── components/
│   │   │   ├── ui/         # Primitivas Dark Bento Grid (BentoCard, Button, SegmentedControl, Skeleton)
│   │   │   └── soc/        # Sidebar, Header, MetricStrip, FlowsTable, RiskBadge, ThreatBadge, FlowDetailDrawer
│   │   ├── pages/          # OverviewPage, ThreatLabPage, ModelAnalyticsPage, FileInspectorPage
│   │   ├── services/       # Cliente REST y hook useAlertWebSocket
│   │   └── types/          # Tipos TypeScript alineados con la API
│   ├── Dockerfile
│   └── nginx.conf
├── demo_samples/           # mixed_traffic_demo.csv y sample_capture.pcap
├── DESIGN.md               # Fuente de verdad del sistema de diseño Dark Bento Grid
├── REDESIGN_PLAN.md        # Auditoría UI/UX y plan por etapas
├── docker-compose.yml
└── README.md
```
