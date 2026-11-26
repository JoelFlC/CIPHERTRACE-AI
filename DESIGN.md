---
name: CIPHERTRACE AI — Design System
description: Sistema de diseño Dark Bento Grid para la consola SOC de detección pasiva de amenazas en tráfico cifrado (sin descifrado de payload).
colors:
  bg-canvas: "#101416"
  surface-sidebar: "#151A1E"
  surface-primary: "#1C2226"
  surface-secondary: "#272F35"
  border-subtle: "#343D43"
  text-primary: "#F2F4F5"
  text-secondary: "#A1ABB3"
  text-muted: "#8E99A2"
  accent-blue: "#5795F2"
  accent-blue-light: "#79ABFF"
  warning-amber: "#F2A544"
  critical-red: "#E56B6F"
  critical-red-text: "#F08A8D"
  success-green: "#36C995"
  vector-aitm: "#9D8CF5"
  vector-aitm-text: "#B0A1F8"
typography:
  page-title:
    fontFamily: "Inter, Manrope, system-ui, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.015em"
  section-title:
    fontFamily: "Inter, Manrope, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.35
    letterSpacing: "-0.01em"
  module-title:
    fontFamily: "Inter, Manrope, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "-0.005em"
  metric-hero:
    fontFamily: "Inter, Manrope, system-ui, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: "-0.02em"
  metric-strip:
    fontFamily: "Inter, Manrope, system-ui, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  body:
    fontFamily: "Inter, Manrope, system-ui, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "0em"
  label:
    fontFamily: "Inter, Manrope, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "0em"
  technical:
    fontFamily: "JetBrains Mono, ui-monospace, SFMono-Regular, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "0em"
rounded:
  sm: "6px"
  md: "10px"
  lg: "16px"
  xl: "20px"
  pill: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  base: "16px"
  lg: "20px"
  xl: "24px"
  2xl: "32px"
  3xl: "48px"
components:
  bento-card:
    backgroundColor: "{colors.surface-primary}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.lg}"
    padding: "{spacing.lg}"
  button-primary:
    backgroundColor: "{colors.accent-blue}"
    textColor: "{colors.bg-canvas}"
    rounded: "{rounded.md}"
    padding: "8px 14px"
  button-primary-hover:
    backgroundColor: "{colors.accent-blue-light}"
  button-secondary:
    backgroundColor: "{colors.surface-secondary}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.md}"
    padding: "8px 14px"
  input-field:
    backgroundColor: "{colors.surface-secondary}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
---

# DESIGN SYSTEM — CIPHERTRACE AI

**Versión:** 2.0 (Especificación Normativa)  
**Estado:** Propuesto — Pendiente de Aprobación (Fase 1)  
**Dirección Visual:** Dark Bento Grid / Minimalismo Operativo de Ciberseguridad  
**Creative North Star:** *"Precision Telemetry Bento"*

---

## 1. Filosofía Visual y Principios de UX

**CIPHERTRACE AI** es una consola SOC (*Security Operations Center*) de operación continua orientada a analistas de ciberseguridad. La interfaz pertenece al modo **Operate**: el diseño debe desaparecer dentro de la tarea, permitiendo escanear flujos cifrados, anomalías, explicabilidad XAI y métricas de Machine Learning con precisión quirúrgica y mínima fatiga visual.

El lenguaje visual adopta un **Dark Bento Grid contemporáneo**: módulos asimétricos sobre superficies oscuras diferenciadas por tono, protagonismo del azul para la telemetría e interacción, tipografía limpia con cifras tabulares y espacio negativo deliberado.

### Principios Rectores

1. **Claridad sobre decoración:** Cada borde, etiqueta, icono o cambio de color debe codificar información operativa real.
2. **Jerarquía sobre densidad:** Lo crítico (KPIs de amenaza, evolución del riesgo, alertas activas) domina el primer plano; la configuración secundaria y los detalles técnicos profundos se revelan de forma progresiva.
3. **Consistencia transversal:** Las cuatro vistas (`Overview`, `ThreatLab`, `ModelAnalytics`, `FileInspector`) y el `FlowDetailDrawer` comparten exactamente los mismos tokens, radios, tablas, controles y vocabulario de estados.
4. **Superficies compartidas:** **The Shared-Surface Rule.** Un Bento Grid no consiste en encerrar cada dato en una tarjeta independiente. Las métricas relacionadas conviven en una misma superficie (`MetricStrip`) separadas por divisores *hairline* sutiles.
5. **Telemetría liderada por azul:** **The Blue-Led Data Rule.** El azul (`#5795F2` / `#79ABFF`) lidera las visualizaciones de datos, barras de progreso, líneas de tendencia e interacciones primarias.
6. **Contención semántica:** **The Restraint Rule.** El rojo, ámbar y verde se reservan estrictamente para estados de riesgo, conectividad o validación. Nunca se usan como adorno ni compiten varios acentos saturados dentro de un mismo módulo.
7. **Integridad operativa:** Ninguna decisión estética puede ocultar valores reales, truncar ejes de forma engañosa ni alterar umbrales o lógica de detección.

---

## 2. Paleta de Colores y Tokens Semánticos

### 2.1 Superficies, Bordes y Texto

| Token CSS | Hex / Valor | Rol Funcional | Contraste Estimado |
| :--- | :--- | :--- | :--- |
| `--bg-canvas` | `#101416` | Lienzo principal de la aplicación (`body`, `<main>`). | Base |
| `--surface-sidebar` | `#151A1E` | Capa neutral intermedia exclusiva para Sidebar y Header sticky. | Diferenciación sutil vs canvas |
| `--surface-primary` | `#1C2226` | Contenedores Bento principales (`BentoCard`, `FlowDetailDrawer`). | Base de lectura |
| `--surface-secondary` | `#272F35` | Controles interactivos, inputs, *segmented controls*, hover de filas, chips neutros. | Base de control |
| `--border-subtle` | `#343D43` | Bordes de inputs, tooltips y separadores visibles. | Separador estructural |
| `--border-hairline` | `rgba(52, 61, 67, 0.65)` | Divisores internos entre columnas/filas de un mismo módulo Bento. | Separador ligero |
| `--text-primary` | `#F2F4F5` | Títulos, valores de métricas, contenido principal y texto activo. | ~14.3:1 sobre `#1C2226` |
| `--text-secondary` | `#A1ABB3` | Subtítulos, descripciones, cabeceras de tabla y etiquetas de apoyo. | ~6.7:1 sobre `#1C2226` (AA/AAA) |
| `--text-muted` | `#8E99A2` | Ticks de gráficas, timestamps secundarios, placeholders y estados inactivos. | ~5.53:1 sobre `#1C2226`, ~4.68:1 sobre `#272F35` (AA) |

### 2.2 Acentos y Estados Semánticos

| Token CSS | Hex Base | Variante Soft (`14%`) | Texto AA sobre Soft | Uso Exclusivo |
| :--- | :--- | :--- | :--- | :--- |
| `--accent-blue` | `#5795F2` | `rgba(87, 149, 242, 0.14)` | `#79ABFF` (5.63:1) | Botón primario (con texto `#101416`, 6.16:1), serie principal en gráficas, barras de progreso, estado activo de navegación, indicador de foco. |
| `--accent-blue-light` | `#79ABFF` | `rgba(121, 171, 255, 0.14)` | `#79ABFF` (5.63:1) | Hover sobre acento azul (texto `#101416`, 8.01:1), resaltado numérico puntual, serie secundaria en comparativas. |
| `--warning-amber` | `#F2A544` | `rgba(242, 165, 68, 0.14)` | `#F2A544` (6.01:1) | Riesgo `MEDIO`, WebSocket `CONECTANDO`, advertencias de privilegios (`CAP_NET_RAW`), métricas `FP`/`FN`. |
| `--critical-red` | `#E56B6F` | `rgba(229, 107, 111, 0.14)` | `#F08A8D` (5.55:1) | Riesgo `ALTO`, línea de umbral crítico, alertas críticas, errores de API/archivo, botón de detención de captura (`#E56B6F` en dots/gráficas/borde, `#F08A8D` en texto sobre fondos *soft*). |
| `--success-green` | `#36C995` | `rgba(54, 201, 149, 0.14)` | `#36C995` (5.85:1) | Riesgo `BAJO` / `BENIGN`, WebSocket `LIVE`, sensor en vivo activo, `TP`/`TN`, confirmación de ejecución exitosa. |

### 2.3 Mapeo Categórico de Vectores de Amenaza (Excepción Documentada)

Los 5 vectores de `ThreatVector` requieren diferenciación unívoca en el gráfico de distribución y en etiquetas de vector sin duplicar el rojo en dos categorías distintas:

| Vector | Etiqueta | Color Asignado | Justificación |
| :--- | :--- | :--- | :--- |
| `BENIGN` | Tráfico Benigno | `#36C995` (`--success-green`) | Tráfico legítimo sin anomalía. |
| `DOH_TUNNEL` | Túnel DoH | `#5795F2` (`--accent-blue`) | Vector de red DNS/HTTPS representado con el azul primario de datos. |
| `EXFILTRATION` | Exfiltración | `#F2A544` (`--warning-amber`) | Anomalía de volumen saliente. |
| `C2_BEACONING` | Beaconing C2 | `#E56B6F` (`--critical-red`) | Canal de comando y control crítico. |
| `PHISHING_AITM` | Phishing AiTM | `#9D8CF5` (`--vector-aitm`) | Índigo-violeta contenido usado **únicamente** para distinguir el 5.º vector en gráficas y tags de vector (`#B0A1F8` en texto sobre fondo soft); la severidad del flujo sigue usando `RiskBadge` en `#F08A8D` / `#E56B6F`. |

### 2.4 Reglas de Color

1. **Prohibido usar color como único canal:** Toda severidad (`ALTO`, `MEDIO`, `BAJO`) debe acompañarse de etiqueta textual y marcador geométrico (punto o icono).
2. **Prohibido el neón y el cian heredado:** Se eliminan `#06B6D4`, `#0B0F19`, `#111827` y `#0D1321` de toda la interfaz.
3. **Máximo un acento dominante por módulo:** Si un módulo tiene una gráfica azul, sus controles internos usan neutros (`#272F35`, `#F2F4F5`) para no competir visualmente.

---

## 3. Tipografía y Escala Tipográfica

### 3.1 Familias Tipográficas

- **Principal (UI, títulos, métricas y cuerpo):** `'Inter', 'Manrope', system-ui, -apple-system, sans-serif` (ambas fuentes cargadas en `index.html`).
- **Técnica puntual:** `'JetBrains Mono', ui-monospace, SFMono-Regular, monospace` reservada **estrictamente** para literales de red y sistema: direcciones `IP:puerto`, dominios `SNI`, `flow_id`, filtros `BPF`, rutas `/api/*` y nombres crudos de atributos (`double_hop_latency_ms`).
- **Cifras tabulares:** Todos los KPIs, porcentajes, latencias, timestamps y columnas numéricas usan `Inter` con `font-variant-numeric: tabular-nums` (clase `.tabular-nums`). Se elimina el uso indiscriminado de monoespaciada en KPIs y badges de estado.

### 3.2 Escala Tipográfica Fija (Modo Operate)

| Rol | Tamaño (`rem` / `px`) | Peso | Line-Height | Tracking | Uso y Reglas |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Título de Página** | `1.25rem` (`20px`) | `600` | `1.3` | `-0.015em` | Título principal en el Header sticky. |
| **Encabezado de Sección** | `1rem` (`16px`) | `600` | `1.35` | `-0.01em` | Títulos de bloques mayores o portales comparativos. |
| **Título de Módulo Bento** | `0.875rem` (`14px`) | `600` | `1.4` | `-0.005em` | Cabecera de cada `BentoCard`. |
| **Métrica Hero (KPI)** | `1.75rem` (`28px`) | `600` | `1.15` | `-0.02em` | Valor principal en `MetricStrip` (`tabular-nums`). Nunca superar `32px`. |
| **Métrica Secundaria** | `1.375rem` (`22px`) | `600` | `1.2` | `-0.015em` | Métricas de resumen en sub-vistas o comparativas (`tabular-nums`). |
| **Texto General** | `0.8125rem` (`13px`) | `400` | `1.5` | `0em` | Celdas de tabla, explicaciones XAI, descripciones de flujo (`max-w-[65ch]` en prosa). |
| **Metadatos / Subtítulos** | `0.75rem` (`12px`) | `400–500` | `1.45` | `0em` | Subtítulos de módulos, labels de formulario, ejes secundarios (`#A1ABB3`). |
| **Etiquetas y Badges** | `0.6875rem` (`11px`) | `500` | `1.25` | `0em` | Badges de riesgo, pills de filtro, cabeceras de tabla en *sentence case* (evitar `ALL CAPS` con tracking ancho). |

---

## 4. Espaciado, Dimensiones y Sistema de Superficies

### 4.1 Escala de Espaciado (Base 4px)

- `4px` (`gap-1`): Separación mínima entre icono/dot y etiqueta dentro de un badge.
- `8px` (`gap-2`): Relación directa entre elementos de un mismo control (ej. título + subtítulo de módulo).
- `12px` (`gap-3`): Separación interna en listas compactas, filas de formulario o botones en barra.
- `16px` (`gap-4` / `p-4`): Separación estándar entre módulos del **Bento Grid** y padding compacto.
- `20px` (`p-5`): Padding estándar de los módulos `BentoCard`.
- `24px` (`space-y-6`): Separación vertical entre filas o secciones principales de una página.
- `32px` (`p-8`): Padding en estados vacíos (*empty states*) y dropzones amplios.

### 4.2 Sistema de Elevación Tonal (Sin Sombras Decorativas)

La profundidad se construye mediante **3 planos tonales**, nunca mediante sombras pesadas ni brillos neón:

1. **Plano 0 — Lienzo (`#101416`):** Fondo general de la ventana.
2. **Plano 1 — Superficie Primaria (`#1C2226`):** Módulos Bento y paneles de contenido, delimitados por `1px solid rgba(52, 61, 67, 0.7)`.
3. **Plano 2 — Superficie Secundaria (`#272F35`):** Controles interactivos, inputs, pestañas activas de *segmented controls* y bloques internos puntuales.

**Excepción de sombra:** Únicamente los elementos flotantes sobre el plano (`FlowDetailDrawer`, tooltips de Recharts y sidebar móvil abierta) utilizan `box-shadow: 0 16px 40px rgba(0, 0, 0, 0.45)`.

### 4.3 Bordes y Radios

| Nivel | Radio | Aplicación |
| :--- | :--- | :--- |
| **Pequeño (`sm`)** | `6px` (`rounded-md`) | Badges de riesgo, tags técnicos, ítems internos de *segmented control*. |
| **Estándar (`md`)** | `10px` (`rounded-[10px]`) | Botones, inputs, selects, ítems de navegación en sidebar, contenedores de alerta. |
| **Módulo (`lg`)** | `16px` (`rounded-2xl`) | `BentoCard`, `MetricStrip`, contenedores de tabla principal, dropzone. |
| **Overlay (`xl`)** | `20px` (`rounded-l-[20px]`) | `FlowDetailDrawer` y paneles modales/deslizables. |
| **Píldora (`pill`)** | `9999px` (`rounded-full`) | Puntos de estado, pills de protocolo/vector cuando corresponda. |

---

## 5. Arquitectura Bento Grid

- **Grilla base:** `grid-cols-1 gap-4 xl:grid-cols-12`.
- **Asimetría intencional:** Asignar mayor ancho (`col-span-7` o `col-span-8`) a la visualización o tabla operativa principal y menor ancho (`col-span-5` o `col-span-4`) a desgloses secundarios o guías.
- **Prohibición de anidación gratuita:** Nunca colocar tarjetas con borde y fondo distinto dentro de otra tarjeta si basta con una lista limpia, un divisor *hairline* (`border-[#343D43]/60`) o espaciado vertical.
- **Máximo 1 nivel de sub-contenedor:** Solo se permite un bloque `#272F35` dentro de `#1C2226` para inputs, *segmented controls* o comparativas puntuales (ej. fórmula del score híbrido o matriz de confusión 2×2).

---

## 6. Componentes y Patrones Reutilizables

### 6.1 Shell de Navegación (Sidebar + Header)

- **Sidebar (`248px` fijo en `lg+`, drawer en `<1024px`):**
  - Fondo `--surface-sidebar` (`#151A1E`) con borde derecho `1px solid rgba(52, 61, 67, 0.65)`.
  - **Identidad:** Logotipo limpio + `CIPHERTRACE AI` + subtítulo discreto `SOC Pasivo TLS`.
  - **Estado WebSocket sereno:** Indicador compacto (`LIVE`, `CONECTANDO`, `OFFLINE`) sin bordes neón ni animación infinita; incluye botón de reconexión solo si está `OFFLINE`.
  - **Navegación (4 vistas):** Ítems `rounded-[10px]` con estado activo en fondo `rgba(87, 149, 242, 0.12)` y texto `#F2F4F5` (icono en `#5795F2`). Badge numérico discreto en `Overview` cuando `active_alerts > 0`.
  - **Footer consolidado:** Resumen técnico compacto del Motor Híbrido (`w_mlp`, `w_ae`, `threshold` y estado del modelo), eliminando el duplicado del estado del Sensor Híbrido que ya vive en `OverviewPage`.
- **Header Sticky (`56px` / `h-14`):**
  - Fondo `rgba(21, 26, 30, 0.88)` con `backdrop-blur-md` y borde inferior hairline.
  - Izquierda: botón menú móvil (`<lg`), título de vista (`20px`) y subtítulo breve (`12px`, oculto en móvil estrecho).
  - Derecha: pill sobria `Análisis Pasivo (Sin Descifrado)` y botón secundario `Actualizar`.

### 6.2 Primitivas de UI (`components/ui/`)

1. **`BentoCard`:** Contenedor base (`bg-[#1C2226] rounded-2xl border border-[#343D43]/70 p-5`) con cabecera opcional (`title`, `subtitle`, `action` alineada a la derecha) y opción `noPadding` para tablas que llegan al borde.
2. **`MetricStrip`:** Módulo Bento único dividido en 4 columnas (`grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 divide-y sm:divide-y-0 xl:divide-x divide-[#343D43]/60`) para mostrar KPIs relacionados sin fragmentar la pantalla en 4 cajas aisladas.
3. **`Button`:** Variantes `primary` (`#5795F2` texto `#101416`, 6.16:1), `secondary` (`#272F35` borde `#343D43`), `ghost` y `danger-subtle` (fondo `#E56B6F/14` texto `#F08A8D`, 5.55:1 para detener captura). Todos incluyen `active:scale-[0.97]`, `focus-visible` en azul y estado `disabled`/`loading`.
4. **`SegmentedControl`:** Selector de opciones mutuamente excluyentes (`TODOS/ALTO/MEDIO/BAJO`, `1/3/5/10`, `Fase 1/Fase 2`) sobre fondo `#101416`/`#272F35`, sin animaciones lentas.
5. **`EmptyState` & `Skeleton`:** Estados vacíos centrados con icono `20px` en `#8E99A2`, mensaje accionable y sin bordes punteados agresivos; esqueletos tonales en `#272F35` para carga inicial (`loading === true`) en lugar de spinners sueltos.
6. **`AlertBanner`:** Mensajes de error o advertencia (`CAP_NET_RAW`, error de API, archivo inválido) con icono `16px`, texto claro y contraste verificado.

### 6.3 Componentes de Dominio SOC (`components/soc/`)

1. **`RiskBadge`:** Pill compacta (`rounded-md`, `11px`, peso `500`) con punto indicador (`6px`), etiqueta (`ALTO`, `MEDIO`, `BAJO`) y score opcional en `tabular-nums`.
2. **`ThreatBadge`:** Muestra la etiqueta legible (`THREAT_LABELS`) o el identificador de vector con indicador de color categórico discreto (`6px` dot) sobre fondo neutro `#272F35`, evitando convertir cada fila de tabla en un arcoíris de bordes coloreados.
3. **`FlowsTable`:** Tabla operativa unificada para `OverviewPage` y `FileInspectorPage` (y adaptable a `ThreatLabPage`).
   - Cabeceras en `12px` *sentence case* (`#A1ABB3`), sin `ALL CAPS` agresivos.
   - Columnas numéricas alineadas a la derecha con `tabular-nums`.
   - Filas interactivas (`tabIndex={0}`, `role="button"` o botón semántico en celda, activación con `Enter`/`Space`), estado hover sutil (`hover:bg-[#272F35]/55`) y resaltado de fila seleccionada cuando `FlowDetailDrawer` está abierto.
4. **`FlowDetailDrawer`:** Panel lateral derecho (`max-w-xl`, `#1C2226`, `rounded-l-[20px]`) con:
   - Cabecera fija con `flow_id`, `RiskBadge`, `ThreatBadge`, timestamp y origen.
   - Confirmación discreta de análisis pasivo sin descifrado.
   - Metadatos de red en grilla limpia sin cajas redundantes.
   - Desglose de Score Híbrido (barra azul/semántica con marcador de umbral) + 4 sub-modelos.
   - Bloque **XAI — Factores Determinantes** (Top 3 desviaciones `z-score` con valor observado vs media benigna y explicación en español).
   - Acordeón colapsable de los 18 atributos pasivos.
   - Cierre con `Escape`, clic fuera o botón `X`, y retorno de foco al elemento disparador.

---

## 7. Iconografía

---

## 7. Iconografía

- **Librería:** `lucide-react` exclusivamente.
- **Trazo:** `strokeWidth={1.75}` consistente.
- **Tamaños:** `14px` (`h-3.5 w-3.5`) en botones compactos/badges, `16px` (`h-4 w-4`) en navegación y cabeceras de módulo, `20px` (`h-5 w-5`) en *empty states* y dropzone en `#8E99A2`.
- **Regla de utilidad:** Prohibido añadir iconos decorativos en cada métrica del `MetricStrip` o en cada paso cuando la tipografía ya establece la jerarquía.

---

## 8. Gráficos y Visualización de Datos (Recharts)

1. **Color protagonista:** Las áreas, barras principales y líneas de mejor aptitud usan `#5795F2` (relleno degradado vertical muy sutil de `0.24` a `0.00` opacidad) y `#79ABFF` para contraste secundario.
2. **Ejes y grilla:** `CartesianGrid` solo horizontal (`vertical={false}`) con trazo `rgba(52, 61, 67, 0.45)`. `axisLine={false}` y `tickLine={false}` en `XAxis` e `YAxis`. Ticks en `#8E99A2`, `11px`, `Inter` `tabular-nums`.
3. **Umbrales:** `ReferenceLine` en `#E56B6F` (`strokeDasharray="4 4"`, `strokeOpacity={0.75}`).
4. **Tooltips:** Contenedor unificado (`ChartTooltip`) en `#272F35` con borde `#343D43`, radio `10px`, sombra suave y tipografía `12px` `tabular-nums`.
5. **Integridad de escala:** Los gráficos comparativos porcentuales (ej. `ModelAnalyticsPage`) **deben iniciar en `0%`** (`domain={[0, 100]}`) para no exagerar diferencias visuales ni distorsionar el recall de modelos no supervisados.
6. **Streaming en vivo:** `isAnimationActive={false}` en gráficos alimentados por WebSocket para evitar re-renderizados temblorosos.

---

## 9. Animaciones y Microinteracciones (Principios de Emil Kowalski)

### 9.1 Curvas y Duraciones Estándar

```css
:root {
  --ease-out: cubic-bezier(0.23, 1, 0.32, 1);
  --ease-in-out: cubic-bezier(0.77, 0, 0.175, 1);
  --ease-drawer: cubic-bezier(0.32, 0.72, 0, 1);
}
```

| Interacción | Propiedades Animadas | Duración | Curva |
| :--- | :--- | :--- | :--- |
| Presión de botón (`:active`) | `transform: scale(0.97)` | `140ms` | `--ease-out` |
| Hover de botones, filas, nav | `background-color`, `border-color`, `color` | `150ms` | `ease` |
| Controles segmentados / Tabs | `background-color`, `color` | `160ms` | `--ease-out` |
| Tooltips / Popovers | `opacity`, `transform: scale(0.96 -> 1)` | `150ms` | `--ease-out` |
| `FlowDetailDrawer` (entrada) | `transform: translateX(100% -> 0)`, backdrop `opacity` | `260ms` | `--ease-drawer` |
| `FlowDetailDrawer` (salida) | `transform: translateX(0 -> 100%)`, backdrop `opacity` | `200ms` | `--ease-out` |

### 9.2 Reglas Estrictas de Movimiento

1. **Solo `transform` y `opacity` para movimiento:** Prohibido animar `width`, `height`, `margin`, `padding`, `top` o `left`. Prohibido `transition: all`.
2. **Prohibido `ease-in`:** Retrasa la respuesta inicial donde el usuario está mirando.
3. **Prohibido `scale(0)`:** Cualquier entrada con escala parte mínimo de `scale(0.96)` + `opacity: 0`.
4. **Sin coreografías de entrada al cargar páginas:** En modo *Operate*, las pantallas cargan listas para trabajar sin cascadas ni *slide-up* repetitivos.
5. **Sin animaciones infinitas de distracción:** Se elimina `animate-ping` del indicador `LIVE` y se reemplaza por un punto sólido `#36C995` con halo estático sutil (`box-shadow: 0 0 0 4px rgba(54, 201, 149, 0.16)`). Los únicos spinners permitidos son los de carga activa de peticiones (`isAnalyzing`, `captureBusy`, `runningScenario`).
6. **Gating en dispositivos táctiles:** Todo efecto `:hover` con `transform` debe ir dentro de `@media (hover: hover) and (pointer: fine)`.
7. **Accesibilidad (`prefers-reduced-motion: reduce`):** Se eliminan desplazamientos (`translateX`, `scale`) y se sustituyen por transiciones suaves de `opacity` (`150ms ease`) para mantener la comprensión de estado sin provocar mareo.

---

## 10. Estados de Interacción, Responsive y Accesibilidad

- **Estados obligatorios en controles:** `default`, `hover`, `focus-visible` (`ring-2 ring-[#5795F2]/70 ring-offset-2 ring-offset-[#101416]`), `active`, `disabled` (`opacity-50 cursor-not-allowed`), `loading` y `error`.
- **Responsive:**
  - Desktop (`>= 1280px`): Sidebar fija `248px` + Bento Grid de 12 columnas.
  - Tablet (`768px–1279px`): Grillas asimétricas colapsan a 1 o 2 columnas proporcionadas; sidebar fija desde `1024px` (`lg`), drawer en `<1024px`.
  - Móvil (`< 768px`): Apilamiento vertical limpio (`gap-4`), controles de filtro envolventes o deslizables, tablas con `overflow-x-auto` contenido dentro de su `BentoCard` sin desbordar el viewport.
- **Accesibilidad:**
  - Navegación completa por teclado (`Tab`, `Enter`/`Space` en filas de flujo, `Escape` para cerrar `FlowDetailDrawer` o sidebar móvil).
  - Región `aria-live="polite"` para anunciar nuevas alertas críticas recibidas por WebSocket o errores de captura/archivo.
  - Contraste mínimo `4.5:1` en todo texto operativo.

---

## 11. Anti-Patterns Prohibidos

1. Cards anidadas dentro de cards con bordes dobles sin necesidad funcional.
2. Uso de `#06B6D4` (cian), `#0B0F19`, `#111827` o brillos/sombras neón.
3. `transition: all` o animaciones con `ease-in` o `scale(0)`.
4. Indicadores parpadeantes infinitos (`animate-ping`) en estado normal de monitorización.
5. `JetBrains Mono` en KPIs, porcentajes o etiquetas de interfaz.
6. `ALL CAPS` sistemático con `tracking-wider` en cada cabecera o etiqueta.
7. Gráficos comparativos con eje Y truncado (`domain={[80, 100]}`) que distorsionen métricas reales.
8. Duplicación de bloques informativos entre la Sidebar y las vistas principales.

---

## 12. Integridad Funcional

Este sistema de diseño rige **exclusivamente la capa de presentación (`frontend/src/`)**. Quedan explícitamente fuera de alcance y sin alteración:

- Lógica de extracción de 18 atributos pasivos y selección genética (`backend/app/ml/`).
- Modelos ML/DL (MLP, PyTorch Autoencoder, Random Forest, Isolation Forest) y pesos/umbrales (`backend/artifacts/ga_config.json`).
- Endpoints REST (`/api/*`), WebSocket (`/ws/alerts`) y portales de laboratorio (`/lab/legit-portal`, `/lab/aitm-proxy`).
- Contratos de tipos e integración en `frontend/src/services/api.ts` y `frontend/src/types/ciphertrace.ts` (salvo la actualización puramente visual de los hexes en `THREAT_COLORS`).
