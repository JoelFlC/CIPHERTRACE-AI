# REDESIGN PLAN — CIPHERTRACE AI

**Fase:** 1 — Auditoría, Design System y Planificación (Pendiente de Aprobación)  
**Alcance:** Exclusivamente capa UI/UX (`frontend/src/`). Cero modificaciones en `backend/` ni en contratos de API/ML/WebSocket.  
**Referencia Normativa:** [DESIGN.md](./DESIGN.md)

---

## 1. Diagnóstico del Estado Actual

### 1.1 Stack Tecnológico y Arquitectura Auditada
- **Frontend:** React `18.3.1`, TypeScript `5.7.2`, Vite `6.1.0`, Tailwind CSS `3.4.17`, Recharts `2.15.1`, Lucide React `0.475.0`.
- **Fuente de datos:** Cliente REST (`frontend/src/services/api.ts`) hacia FastAPI `:8000/api` y hook `useAlertWebSocket` hacia `/ws/alerts` con reconexión exponencial.
- **Tipado:** `frontend/src/types/ciphertrace.ts` (contrato completo alineado con el backend).
- **Estilos actuales:** `index.html`, `tailwind.config.js` (define tokens `soc.*` que casi no se usan) e `index.css` (define `.mono-num` y un `prefers-reduced-motion` que fuerza `0.01ms !important`).

### 1.2 Skills y Metodologías Aplicadas
Se localizarán y aplicaron directamente las tres skills solicitadas:
1. **Emil Kowalski (`emil-design-eng` + `animate`):** Marco de compuertas (frecuencia y propósito), curvas `--ease-out` / `--ease-drawer`, duraciones `<300ms`, feedback táctil `:active { scale(0.97) }`, prohibición de `transition: all` y `ease-in`, eliminación de `animate-ping` permanente, gating de hover táctil y `prefers-reduced-motion` basado en opacidad suave.
2. **Frontend Design (`frontend-design`):** Identidad visual propia alejada del patrón genérico "cyberpunk cian sobre `#0B0F19`", eliminación de *template chrome* (`ALL CAPS` en etiquetas, bordes redundantes en cada micro-dato), agrupación intencional en un **Dark Bento Grid** con espacio negativo.
3. **Impeccable (`impeccable` + `operate.md` + `document.md`):** Enfoque **Modo Operate** (densidad controlada, escala tipográfica fija `1.15–1.2`, segunda capa neutral para Sidebar, skeletons de carga en lugar de spinners sueltos, estados vacíos orientados a la acción, foco visible y validación de integridad de datos).

### 1.3 Hallazgos Transversales Críticos
1. **Tokens ignorados y hexes hardcodeados:** Aunque `tailwind.config.js` define `soc.bg`, `soc.surface` y `soc.accent`, casi todos los archivos usan hexes inline (`#0B0F19`, `#111827`, `#0D1321`, `#1F2937`, `#06B6D4`).
2. **Triple anidación visual:** Contenedores `#111827` con borde `#1F2937` que contienen cajas `#0B0F19` con borde `#1F2937` que a su vez contienen badges/sub-bloques `#111827`. Fragmenta la lectura y genera ruido visual.
3. **Abuso de monoespaciada y mayúsculas:** `.mono-num` (`JetBrains Mono`) se aplica a KPIs, porcentajes, botones, badges y etiquetas de navegación, restando jerarquía a los datos realmente técnicos (`IP:port`, `SNI`, `flow_id`).
4. **Falta de sistema de componentes:** No existen primitivas compartidas para tarjetas, botones, tablas, *segmented controls*, tooltips de gráficos, skeletons ni estados vacíos; `OverviewPage` y `FileInspectorPage` duplican tablas y filtros casi idénticos.
5. **Accesibilidad incompleta:** Filas `<tr>` con `onClick` sin `tabIndex` ni soporte de teclado (`Enter`/`Space`), ausencia de `aria-live` para alertas nuevas y sin retorno de foco al cerrar `FlowDetailDrawer`.
6. **Animaciones y distracción:** Uso de `transition-all` en barras de progreso, `animate-ping` infinito en el indicador `LIVE` de la Sidebar, ausencia de feedback `:active` en botones y `FlowDetailDrawer` sin transición de entrada/salida.

---

## 2. Inventario Completo de Pantallas y Módulos

| Superficie | Archivo | Rol Operativo |
| :--- | :--- | :--- |
| **Shell Global & Header** | `frontend/src/App.tsx` | Orquestación de estado, polling de captura, WebSocket, header sticky y montaje de vistas. |
| **Navegación Lateral** | `frontend/src/components/Sidebar.tsx` | Navegación entre las 4 vistas, estado `/ws/alerts`, badge de alertas y resumen de motor/sensor. |
| **Vista 1: Live SOC Overview** | `frontend/src/pages/OverviewPage.tsx` | Panel Sensor Híbrido, 4 KPIs, gráfico temporal de `risk_score`, distribución por vector y tabla de flujos filtrable. |
| **Vista 2: Laboratorio AiTM** | `frontend/src/pages/ThreatLabPage.tsx` | Inyección controlada de los 5 escenarios, comparativa de portales locales, guía en 3 pasos y feed WebSocket en vivo. |
| **Vista 3: Motor IA & AG** | `frontend/src/pages/ModelAnalyticsPage.tsx` | Métricas `k=5`, procedencia del dataset, curvas de convergencia AG (Fase 1/2), mapa 18→8, matriz de confusión y comparativa de modelos. |
| **Vista 4: Inspector PCAP / CSV** | `frontend/src/pages/FileInspectorPage.tsx` | Carga Drag & Drop `.pcap/.pcapng/.csv`, resumen de análisis offline y tabla flujo por flujo. |
| **Overlay XAI** | `frontend/src/components/FlowDetailDrawer.tsx` | Inspección profunda de flujo: verificación pasiva, metadatos, scores por modelo, Top 3 XAI (`z-score`) y 18 atributos. |
| **Vistas Backend (Fuera de alcance)** | `backend/app/lab/aitm_lab.py` | Portales HTML `/lab/legit-portal` y `/lab/aitm-proxy`. **Se conservan intactos.** |

---

## 3. Problemas Identificados por Pantalla

### 3.1 Shell & Sidebar (`App.tsx`, `Sidebar.tsx`)
- **Duplicación operativa:** El footer de `Sidebar.tsx` (líneas 236–249) muestra el estado del `Sensor Híbrido`, duplicando el panel completo que ya ocupa la parte superior de `OverviewPage.tsx`.
- **Ruido visual en estado LIVE:** El bloque de WebSocket usa borde verde brillante y `animate-ping` continuo, distrayendo la visión periférica durante la monitorización.
- **Descripciones redundantes en nav:** Cada botón del sidebar muestra dos líneas (`label` + `description`), recargando la barra lateral cuando el header ya muestra el subtítulo de la vista activa.

### 3.2 Vista 1: Live SOC Overview (`OverviewPage.tsx`)
- **Jerarquía invertida:** El formulario de configuración del `Sensor Híbrido` (interfaz, filtro BPF, ventana en segundos, botón) ocupa el primer bloque superior completo (líneas 235–395), empujando los KPIs y las gráficas de telemetría hacia abajo.
- **4 tarjetas KPI idénticas:** Mismo tamaño y peso visual sin jerarquía ni superficie compartida.
- **Leyenda sobre-fragmentada:** En "Distribución por Vector de Amenaza" (líneas 592–621), cada una de las 5 categorías es una mini-caja con borde y fondo `#0B0F19` al lado del donut chart.
- **Tabla repetitiva:** Código de tabla acoplado a la página en lugar de reutilizarse con `FileInspectorPage`.

### 3.3 Vista 2: Laboratorio AiTM & Inyección (`ThreatLabPage.tsx`)
- **5 tarjetas de escenario saturadas:** Cada tarjeta en `xl:grid-cols-5` mezcla icono con borde coloreado, código `SCENARIO` en esquina, título, subtítulo, caja anidada de `telemetryHint` y botón cian (líneas 178–249).
- **Portales con bordes semánticos pesados:** Las tarjetas de `Portal Legítimo` y `Proxy Inverso AiTM` usan bordes gruesos verde/rojo (`border-emerald-500/30`, `border-red-500/30`) que compiten con la guía paso a paso.
- **Triple anidación en la guía:** La guía de 3 pasos encierra cada `<li>` en una caja `#0B0F19` dentro de la tarjeta `#111827`.

### 3.4 Vista 3: Motor IA & Algoritmo Genético (`ModelAnalyticsPage.tsx`)
- **Distorsión de escala en BarChart (Hallazgo crítico):** Línea 643 fija `YAxis domain={[80, 100]}` mientras el Autoencoder e Isolation Forest tienen recall de `30.66%` y `28.73%` y F1 de `45.22%` y `42.98%`. Esto recorta o distorsiona visualmente las barras reales debajo del 80%.
- **Redundancia de pesos AG:** Los pesos `w_mlp`, `w_ae` y `threshold` aparecen en la 4.ª tarjeta del strip superior (líneas 271–282) y se repiten exactamente igual debajo del mapa de atributos (líneas 520–531).
- **Procedencia del dataset fragmentada:** 5 mini-cajas por clase + 3 mini-cajas por archivo dentro de la misma sección (líneas 320–355).
- **Gráfico multicolor innecesario:** El `BarChart` usa cian + verde + ámbar simultáneamente en lugar de liderar con la familia azul (`#5795F2`, `#79ABFF`, `#A1ABB3`).

### 3.5 Vista 4: Inspector Pasivo PCAP / CSV (`FileInspectorPage.tsx`)
- **Estado inicial desbalanceado:** Cuando no hay archivo cargado (`result === null`), la página muestra únicamente una caja grande con borde punteado, dejando gran parte del viewport vacío sin contexto de formatos o capacidades pasivas.
- **Duplicación de KPIs y Tabla:** Repite 4 tarjetas individuales y una tabla casi idéntica a `OverviewPage`.

### 3.6 Overlay: FlowDetailDrawer (`FlowDetailDrawer.tsx`)
- **Entrada/salida abrupta:** Se monta/desmonta sin transición `--ease-drawer` ni gestión de retorno de foco.
- **Exceso de cajas anidadas:** El desglose de modelos, cada tarjeta XAI (Top 3) y los 18 atributos pasivos usan bordes completos dentro de secciones ya bordeadas.

---

## 4. Propuesta de Reorganización de la Información (Bento Grid)

### 4.1 Shell Global (`Sidebar` + `Header`)
- **Conservar:** 4 vistas, estado de conexión `/ws/alerts` con botón de reconexión, contador de alertas activas en `Overview`, resumen de pesos del Motor Híbrido y pill `Análisis Pasivo (Sin Descifrado)` + botón `Actualizar`.
- **Simplificar:** Eliminar el bloque duplicado de `Sensor Híbrido` del footer del sidebar; limpiar los ítems de navegación a icono + etiqueta (1 línea); eliminar `animate-ping`.
- **Reorganizar:** Sidebar de `248px` en `#151A1E` con separadores hairline sutiles y estado `LIVE` sereno.

### 4.2 Vista 1: Live SOC Overview (`OverviewPage.tsx`)
- **Conservar:** Todas las métricas KPI, control completo del Sensor Híbrido (interfaz, BPF, ventana, Start/Stop, contadores de paquetes/flujos/alertas, aviso `CAP_NET_RAW`), evolución temporal de `risk_score`, distribución por vector y tabla filtrable con acceso a `FlowDetailDrawer`.
- **Simplificar:** Unificar los 4 KPIs en un `MetricStrip` compartido; reemplazar las 5 mini-cajas de leyenda por una lista limpia con barras proporcionales horizontales en azul/semántico.
- **Reorganizar:** Subir los KPIs y gráficos al primer plano del viewport; convertir el `Sensor Híbrido` en una barra Bento compacta de estado/acción rápida (con despliegue inline o fila de controles limpia debajo de los KPIs/gráficos o integrada sin dominar el tercio superior).

```text
+-------------------------------------------------------------------------+
| MetricStrip (12 cols): Flujos | Alertas Activas | Latencia | Anomalía   |
+-----------------------------------------+-------------------------------+
| Evolución Temporal Risk Score (7 cols)  | Distribución Vector (5 cols)  |
| AreaChart Azul (#5795F2) + Threshold    | Donut + Lista limpia (sin     |
|                                         | mini-cajas anidadas)          |
+-----------------------------------------+-------------------------------+
| Sensor Híbrido — Barra Operativa Compacta (12 cols)                     |
| Estado + Contadores inline | Interfaz | Filtro BPF | Ventana | Acción   |
+-------------------------------------------------------------------------+
| FlowsTable (12 cols) + SegmentedControl (TODOS | ALTO | MEDIO | BAJO)   |
+-------------------------------------------------------------------------+
```

### 4.3 Vista 2: Laboratorio AiTM & Inyección (`ThreatLabPage.tsx`)
- **Conservar:** Selector de lote (`1, 3, 5, 10`), los 5 escenarios simulables con su feedback de ejecución (`count`, `alerts`), enlaces a `/lab/legit-portal` y `/lab/aitm-proxy`, guía en 3 pasos y feed WebSocket en tiempo real con `capturedDemoToken` y `double_hop_latency_ms`.
- **Simplificar:** Eliminar las sub-cajas dentro de cada tarjeta de escenario y la triple anidación en la guía de 3 pasos; usar bordes sutiles estándar en los portales con un badge semántico discreto.
- **Reorganizar:** Distribución Bento asimétrica para la sección del laboratorio (7 cols comparativa de portales + 5 cols guía secuencial limpia) y banda superior unificada para los 5 escenarios.

```text
+-------------------------------------------------------------------------+
| Inyección Controlada de Tráfico (12 cols) + Selector Lote [1|3|5|10]    |
| Grid 5 escenarios compactos sobre superficie limpia                     |
+-----------------------------------------+-------------------------------+
| Portales Comparativos AiTM (7 cols)     | Guía de Demo en 3 Pasos       |
| [Portal Legítimo] | [Proxy AiTM Demo]   | Lista numerada limpia (5 cols)|
+-----------------------------------------+-------------------------------+
| Feed en Tiempo Real del Laboratorio / WebSocket (12 cols)               |
+-------------------------------------------------------------------------+
```

### 4.4 Vista 3: Motor IA & Algoritmo Genético (`ModelAnalyticsPage.tsx`)
- **Conservar:** Todos los KPIs (`total_flows`, `cv_folds`, reducción `8/18`, F1 híbrido, pesos), trazabilidad de `source_breakdown` (`by_class` y `by_file`), curvas Fase 1 / Fase 2, mapa de 18 atributos seleccionados/descartados, matriz de confusión 2×2 y comparativa de los 5 modelos.
- **Simplificar:** Eliminar el bloque duplicado de pesos debajo del mapa de atributos; unificar `source_breakdown` en una tabla/lista limpia de una sola superficie sin 8 mini-cajas anidadas; cambiar el `BarChart` a tonos azules coherentes y corregir `domain={[0, 100]}`.
- **Reorganizar:**

```text
+-------------------------------------------------------------------------+
| MetricStrip (12 cols): Dataset k=5 | Reducción 8/18 | F1 Híbrido | Pesos|
+------------------------------------+------------------------------------+
| Convergencia AG (6 cols)           | Mapa Atributos 18→8 + Matriz 2×2   |
| LineChart Azul + Tabs Fase 1/2     | Grid compacta + CM (6 cols)        |
+------------------------------------+------------------------------------+
| Tabla Comparativa k=5 (7 cols)     | Rendimiento Comparativo 0-100% (5) |
+------------------------------------+------------------------------------+
| Procedencia y Trazabilidad del Dataset (12 cols, superficie única)      |
+-------------------------------------------------------------------------+
```

### 4.5 Vista 4: Inspector Pasivo PCAP / CSV (`FileInspectorPage.tsx`)
- **Conservar:** Carga Drag & Drop y por teclado, validación `.pcap/.pcapng/.csv`, estado `isAnalyzing`, 4 métricas de resultado, filtro `TODOS/ALTO/MEDIO/BAJO` y tabla flujo por flujo hacia `FlowDetailDrawer`.
- **Simplificar:** Reutilizar `MetricStrip` y `FlowsTable`.
- **Reorganizar:** En estado superior, dividir en Bento `8 cols` (Dropzone limpio) + `4 cols` (Panel de especificación pasiva: formatos soportados, extracción sin descifrado, archivos de muestra en `demo_samples/`).

```text
+--------------------------------------------------+----------------------+
| Zona Drag & Drop PCAP / PCAPNG / CSV (8 cols)    | Alcance Pasivo (4)   |
+--------------------------------------------------+----------------------+
| (Cuando hay resultado) MetricStrip de Análisis (12 cols)                |
+-------------------------------------------------------------------------+
| FlowsTable — Resultados Flujo por Flujo + SegmentedControl (12 cols)    |
+-------------------------------------------------------------------------+
```

---

## 5. Matriz de Componentes: Mantener, Modificar, Unificar o Eliminar

| Elemento | Acción | Detalle |
| :--- | :--- | :--- |
| `services/api.ts` | **Mantener intacto** | Sin cambios en endpoints, fetch ni `useAlertWebSocket`. |
| `types/ciphertrace.ts` | **Mantener contratos** | Solo actualizar los hexes de `THREAT_COLORS` en Fase 2 para alinear con `DESIGN.md`. |
| `index.html`, `tailwind.config.js`, `index.css` | **Modificar** | Incorporar Inter + Manrope, tokens CSS de `DESIGN.md`, curvas `--ease-*` y `prefers-reduced-motion` suave. |
| `BentoCard`, `Button`, `SegmentedControl`, `EmptyState`, `Skeleton`, `AlertBanner`, `ChartTooltip` | **Crear (Unificar)** | Nuevas primitivas en `frontend/src/components/ui/`. |
| `MetricStrip`, `FlowsTable`, `ThreatBadge`, `SensorControlBar` | **Crear (Unificar)** | Componentes de dominio en `frontend/src/components/soc/` para eliminar duplicación entre vistas. |
| `RiskBadge.tsx`, `FlowDetailDrawer.tsx`, `Sidebar.tsx`, `App.tsx` | **Modificar** | Migrar a tokens nuevos, añadir accesibilidad teclado/foco y transiciones Emil Kowalski. |
| Bloque duplicado Sensor en `Sidebar`, bloque duplicado Pesos en `ModelAnalyticsPage`, 5 cajas leyenda en `Overview`, 8 cajas dataset en `ModelAnalytics`, `animate-ping` | **Eliminar** | Eliminación limpia de redundancias visuales sin pérdida de datos. |

---

## 6. Arquitectura Propuesta del Nuevo Sistema de Diseño

```text
frontend/src/
├── index.css                     # Variables CSS (:root tokens, --ease-*, tabular-nums, reduced-motion)
├── types/ciphertrace.ts          # Contratos API + THREAT_COLORS actualizados
├── services/api.ts               # Cliente REST y WebSocket (intacto)
├── components/
│   ├── ui/
│   │   ├── BentoCard.tsx
│   │   ├── Button.tsx
│   │   ├── SegmentedControl.tsx
│   │   ├── EmptyState.tsx
│   │   ├── Skeleton.tsx
│   │   ├── AlertBanner.tsx
│   │   └── ChartTooltip.tsx
│   └── soc/
│       ├── Sidebar.tsx
│       ├── Header.tsx
│       ├── RiskBadge.tsx
│       ├── ThreatBadge.tsx
│       ├── MetricStrip.tsx
│       ├── FlowsTable.tsx
│       ├── SensorControlBar.tsx
│       └── FlowDetailDrawer.tsx
└── pages/
    ├── OverviewPage.tsx
    ├── ThreatLabPage.tsx
    ├── ModelAnalyticsPage.tsx
    └── FileInspectorPage.tsx
```

---

## 7. Componentes Compartidos Prioritarios (Construir Primero)

1. **Capa de Tokens (`index.html`, `tailwind.config.js`, `index.css`):** Define la fuente de verdad de colores, radios, tipografía y curvas de animación.
2. **Primitivas UI (`BentoCard`, `Button`, `SegmentedControl`, `AlertBanner`, `EmptyState`, `Skeleton`, `ChartTooltip`):** Evita que cualquier página vuelva a escribir estilos inline o hexes sueltos.
3. **Componentes SOC (`RiskBadge`, `ThreatBadge`, `MetricStrip`, `FlowsTable`, `FlowDetailDrawer`):** Resuelve de una vez la consistencia de las 4 páginas antes de migrar cada vista.

---

## 8. Orden Recomendado de Implementación (Etapas para Fase 2)

| Etapa | Alcance | Entregable Verificable |
| :--- | :--- | :--- |
| **Etapa 0** | Fundamentos y Tokens | `index.html` (Inter + Manrope), `tailwind.config.js`, `index.css` (`:root` + `--ease-*`), `THREAT_COLORS` en `ciphertrace.ts`. |
| **Etapa 1** | Primitivas UI | `components/ui/*` completos con estados `hover`, `focus-visible`, `active`, `disabled`. |
| **Etapa 2** | Componentes SOC | `RiskBadge`, `ThreatBadge`, `MetricStrip`, `FlowsTable` (accesible por teclado), `FlowDetailDrawer` (con transición `--ease-drawer` y `Escape`). |
| **Etapa 3** | Shell de Aplicación | `Sidebar.tsx`, `Header.tsx` y `App.tsx` integrados con navegación limpia y estado WS sereno. |
| **Etapa 4** | `OverviewPage.tsx` | Bento Grid KPIs, AreaChart azul, Donut + lista limpia, `SensorControlBar` compacto y `FlowsTable`. |
| **Etapa 5** | `ThreatLabPage.tsx` | Escenarios refinados, portales comparativos + guía 3 pasos y feed WebSocket. |
| **Etapa 6** | `ModelAnalyticsPage.tsx` | Métricas `k=5`, convergencia AG azul, mapa 18→8, matriz 2×2, `BarChart` con `domain={[0, 100]}` y trazabilidad unificada. |
| **Etapa 7** | `FileInspectorPage.tsx` + QA | Dropzone 8:4, `MetricStrip`, `FlowsTable`, auditoría responsive, teclado y `npm run build`. |

---

## 9. Dependencias entre Etapas

- **Etapa 0** bloquea a todas las demás (provee tokens y fuentes).
- **Etapa 1** depende de Etapa 0 y bloquea a Etapa 2 y Etapa 3.
- **Etapa 2** depende de Etapa 1 y bloquea a las Etapas 4, 5, 6 y 7.
- **Etapa 3** depende de Etapa 1 y 2 (usa `Button`, `RiskBadge`, tokens).
- **Etapas 4, 5, 6 y 7** pueden ejecutarse secuencialmente (en el orden recomendado 4 → 5 → 6 → 7) una vez completadas las Etapas 0–3.

---

## 10. Riesgos Técnicos y Funcionales

| Riesgo | Impacto | Mitigación |
| :--- | :--- | :--- |
| **Cambio de `domain={[80, 100]}` a `[0, 100]` en `ModelAnalyticsPage`** | Cambia la lectura visual de barras para Autoencoder/Isolation Forest. | **Se solicita aprobación explícita en este plan** porque `[80, 100]` oculta valores reales de ~28–45% y viola el principio de integridad de datos. |
| **Actualización de `THREAT_COLORS` en `types/ciphertrace.ts`** | Cambia colores de vector en gráficas y tags. | Verificar que ningún test dependa de hexes antiguos; mantener exactamente las mismas claves de `ThreatVector`. |
| **Ráfagas WebSocket en tiempo real** | Re-renders frecuentes en `OverviewPage` y `ThreatLabPage`. | Mantener `isAnimationActive={false}` en Recharts y claves estables `${flow.id}-${flow.flow_id}` en `FlowsTable`. |
| **Entorno sin privilegios `CAP_NET_RAW`** | El botón de captura en vivo no debe fallar silenciosamente. | Conservar exactamente la lógica `captureInterfaces?.can_capture === false` y mostrar `AlertBanner` informativo claro. |
| **Desbordamiento en viewports estrechos** | Tablas anchas (`min-w-[860px]`) pueden romper el layout móvil. | Aislar `overflow-x-auto` dentro del contenedor de `FlowsTable` y verificar en `375px` y `768px`. |

---

## 11. Estrategia de Validación y Pruebas

1. **Verificación de tipos y build:** Ejecutar `npm run build` (`tsc --noEmit && vite build`) tras cada bloque mayor y al finalizar la Etapa 7.
2. **Integridad backend/E2E:** Ejecutar `backend/.venv/bin/python backend/tests/test_e2e.py` para confirmar cero regresiones en API y motor ML.
3. **Pruebas funcionales en navegador:**
   - Conexión WebSocket `LIVE` y reconexión al reiniciar backend.
   - Simulación de los 5 escenarios en `ThreatLabPage` + verificación de llegada en tiempo real en `OverviewPage`.
   - Apertura de `FlowDetailDrawer` con clic y con teclado (`Enter`/`Space`), cierre con `Escape` y retorno de foco.
   - Carga de `demo_samples/sample_capture.pcap` y `demo_samples/mixed_traffic_demo.csv` en `FileInspectorPage` + manejo de extensión inválida.
   - Verificación de métricas `k=5` y curvas Fase 1 / Fase 2 en `ModelAnalyticsPage`.
   - Verificación de estado sin backend (`apiError`) y sin `CAP_NET_RAW`.
4. **QA Visual, Responsive y Accesibilidad:** Revisión en `1440px`, `1280px`, `768px` y `375px`, tabulación completa por teclado y comprobación con `prefers-reduced-motion: reduce`.

---

## 12. Criterios de Aceptación

El rediseño se considerará terminado cuando se cumplan todos los puntos siguientes:

- [ ] `npm run build` (`tsc --noEmit && vite build`) finaliza con código `0` y sin advertencias de tipos.
- [ ] Ningún archivo de `frontend/src/` contiene hexes heredados (`#0B0F19`, `#111827`, `#0D1321`, `#06B6D4`) ni `animate-ping` ni `transition-all`.
- [ ] Toda la paleta, tipografía (`Inter` / `Manrope` + `tabular-nums`, `JetBrains Mono` solo en literales técnicos) y radios coinciden con [DESIGN.md](./DESIGN.md).
- [ ] Las 4 vistas, la Sidebar y `FlowDetailDrawer` funcionan íntegramente contra la API y WebSocket reales sin pérdida de datos ni controles.
- [ ] Todas las tablas interactivas y el Drawer son operables por teclado, tienen foco visible y respetan `prefers-reduced-motion`.
- [ ] No hay scroll horizontal global en `1440px`, `1280px`, `768px` ni `375px`.
