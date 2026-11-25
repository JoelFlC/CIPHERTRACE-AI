"""Controlled local Phishing AiTM & Legitimate Portal simulation router (/lab)."""

from __future__ import annotations

import asyncio
import html
import random
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.config import shannon_entropy
from app.db.database import get_db
from app.db.models import persist_evaluation
from app.services.inference_engine import engine
from app.services.ws_manager import ws_manager

router = APIRouter(prefix="/lab", tags=["Controlled AiTM Lab"])


def _render_portal_html(is_aitm: bool) -> str:
    action_url = "/lab/aitm-proxy/login" if is_aitm else "/lab/legit-portal/login"
    banner_html = (
        '<div style="background:#7f1d1d;color:#fecaca;padding:10px 16px;text-align:center;'
        'font-weight:700;font-size:13px;letter-spacing:0.06em;border-bottom:2px solid #ef4444;">'
        "ENTORNO DE LABORATORIO CONTROLADO - PROXY INVERSO AiTM"
        "</div>"
        if is_aitm
        else '<div style="background:#064e3b;color:#a7f3d0;padding:8px 16px;text-align:center;'
        'font-weight:600;font-size:12px;letter-spacing:0.04em;">'
        "ENTORNO DEMO LOCAL - CONEXIÓN TLS DIRECTA"
        "</div>"
    )
    domain_hint = (
        "login-verify-session-portal-academico.cloud-auth.site (Proxy Local)"
        if is_aitm
        else "portal.academico-demo.local"
    )
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Portal Académico Seguro - Demo</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; }}
    .wrap {{ max-width: 440px; margin: 56px auto; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 28px; box-shadow: 0 20px 45px rgba(0,0,0,0.45); }}
    h1 {{ margin: 0 0 6px; font-size: 20px; color: #f8fafc; }}
    .sub {{ font-size: 13px; color: #94a3b8; margin-bottom: 20px; }}
    label {{ display: block; font-size: 12px; color: #cbd5e1; margin: 12px 0 6px; }}
    input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; }}
    button {{ width: 100%; margin-top: 20px; padding: 11px; border: 0; border-radius: 8px; background: #0284c7; color: #fff; font-weight: 600; cursor: pointer; }}
    button:hover {{ background: #0369a1; }}
    .meta {{ margin-top: 16px; font-size: 11px; color: #64748b; border-top: 1px solid #334155; padding-top: 12px; }}
  </style>
</head>
<body>
  {banner_html}
  <div class="wrap">
    <h1>Portal Académico Seguro - Demo</h1>
    <div class="sub">Autenticación institucional ficticia con verificación MFA simulada ({html.escape(domain_hint)})</div>
    <form method="post" action="{action_url}">
      <label for="username">Usuario institucional (demo)</label>
      <input id="username" name="username" type="text" value="estudiante.demo@universidad.local" required />
      <label for="password">Clave de prueba (no se almacena)</label>
      <input id="password" name="password" type="password" value="demo-pass-0000" required />
      <label for="mfa_code">Código MFA simulado (6 dígitos)</label>
      <input id="mfa_code" name="mfa_code" type="text" value="482910" maxlength="6" required />
      <button type="submit">Iniciar sesión segura</button>
    </form>
    <div class="meta">Simulador pasivo CIPHERTRACE AI: el sistema evalúa únicamente metadatos de flujo y latencia, sin registrar credenciales.</div>
  </div>
</body>
</html>"""


async def _parse_login_username(request: Request) -> str:
    """Read only fictional username for UI feedback; discard password/MFA."""
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            return str(body.get("username", "estudiante.demo@universidad.local"))
        except Exception:
            return "estudiante.demo@universidad.local"
    try:
        form = await request.form()
        return str(form.get("username", "estudiante.demo@universidad.local"))
    except Exception:
        return "estudiante.demo@universidad.local"


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    content_type = request.headers.get("content-type", "")
    return "application/json" in accept or "application/json" in content_type


@router.get("/legit-portal", response_class=HTMLResponse)
async def get_legit_portal() -> HTMLResponse:
    """Serve clean fictional institutional portal HTML."""
    return HTMLResponse(content=_render_portal_html(is_aitm=False))


@router.post("/legit-portal/login", response_model=None)
async def post_legit_portal_login(
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """Simulate direct benign login flow and evaluate passively."""
    t0 = time.perf_counter()
    username = await _parse_login_username(request)
    await asyncio.sleep(random.uniform(0.015, 0.035))
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    sni = "portal.academico.edu"
    bytes_sent = 3200.0
    bytes_recv = 28400.0
    flow_meta = {
        "flow_id": f"lab-legit-{uuid.uuid4().hex[:8]}",
        "src_ip": request.client.host if request.client else "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": random.randint(45000, 60000),
        "dst_port": 443,
        "protocol": "TCP",
        "sni": sni,
        "features": {
            "duration_ms": round(1250.0 + latency_ms, 2),
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "byte_asymmetry_ratio": round(
                (bytes_sent - bytes_recv) / (bytes_sent + bytes_recv + 1.0), 4
            ),
            "packets_sent": 14.0,
            "packets_recv": 26.0,
            "iat_mean_ms": 95.0,
            "iat_std_ms": 145.0,
            "pkt_size_mean": 680.0,
            "pkt_size_std": 260.0,
            "pkt_size_max": 1240.0,
            "tls_version_num": 1.3,
            "cipher_suite_count": 18.0,
            "sni_entropy": round(shannon_entropy(sni), 4),
            "sni_length": float(len(sni)),
            "dns_query_rate": 0.4,
            "double_hop_latency_ms": latency_ms,
            "redirect_count": 0.0,
        },
    }

    evaluation = engine.evaluate_flow(flow_meta)
    flow_dict, alert_dict = persist_evaluation(db, evaluation, source="lab_legit_portal")
    await ws_manager.broadcast(
        {
            "event": "flow_evaluated",
            "source": "lab_legit_portal",
            "flow": flow_dict,
            "alert": alert_dict,
        }
    )

    payload = {
        "status": "authenticated_demo",
        "mode": "LEGIT_PORTAL",
        "username": username,
        "session_token": f"legit_session_demo_{uuid.uuid4().hex[:10]}",
        "measured_double_hop_latency_ms": latency_ms,
        "evaluation": flow_dict,
    }
    if _wants_json(request):
        return JSONResponse(content=payload)

    return HTMLResponse(
        content=f"""<!DOCTYPE html><html lang="es"><body style="font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:40px;">
        <div style="max-width:540px;margin:auto;background:#1e293b;padding:24px;border-radius:12px;border:1px solid #10b981;">
        <h2 style="color:#34d399;margin-top:0;">Sesión Legítima Verificada (Demo)</h2>
        <p>Usuario: <strong>{html.escape(username)}</strong></p>
        <p>Latencia observada: <strong>{latency_ms} ms</strong> | Nivel de Riesgo SOC: <strong>{flow_dict['risk_level']}</strong> ({flow_dict['risk_score']:.2f})</p>
        <p><a href="/lab/legit-portal" style="color:#38bdf8;">Volver al portal legítimo</a></p>
        </div></body></html>"""
    )


@router.get("/aitm-proxy", response_class=HTMLResponse)
async def get_aitm_proxy() -> HTMLResponse:
    """Serve cloned portal HTML behind simulated AiTM reverse proxy."""
    return HTMLResponse(content=_render_portal_html(is_aitm=True))


@router.post("/aitm-proxy/login", response_model=None)
async def post_aitm_proxy_login(
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """Simulate double-hop AiTM relay, capture fictional token, and emit SOC alert."""
    t0 = time.perf_counter()
    username = await _parse_login_username(request)

    # Simulate reverse-proxy double-hop relay delay toward upstream legit portal
    await asyncio.sleep(random.uniform(0.22, 0.36))
    measured_double_hop_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    demo_token = f"session_token_demo_{uuid.uuid4().hex[:12]}"
    sni = "login-verify-session-portal-academico.cloud-auth.site"
    bytes_sent = 16420.0
    bytes_recv = 68400.0

    flow_meta = {
        "flow_id": f"lab-aitm-{uuid.uuid4().hex[:8]}",
        "src_ip": request.client.host if request.client else "127.0.0.1",
        "dst_ip": "185.220.101.45",
        "src_port": random.randint(45000, 60000),
        "dst_port": 443,
        "protocol": "TCP",
        "sni": sni,
        "features": {
            "duration_ms": round(6400.0 + measured_double_hop_ms, 2),
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "byte_asymmetry_ratio": round(
                (bytes_sent - bytes_recv) / (bytes_sent + bytes_recv + 1.0), 4
            ),
            "packets_sent": 42.0,
            "packets_recv": 68.0,
            "iat_mean_ms": 195.0,
            "iat_std_ms": 135.0,
            "pkt_size_mean": 540.0,
            "pkt_size_std": 255.0,
            "pkt_size_max": 1360.0,
            "tls_version_num": 1.2,
            "cipher_suite_count": 12.0,
            "sni_entropy": round(shannon_entropy(sni), 4),
            "sni_length": float(len(sni)),
            "dns_query_rate": 1.4,
            "double_hop_latency_ms": measured_double_hop_ms,
            "redirect_count": 5.0,
        },
    }

    evaluation = engine.evaluate_flow(flow_meta)
    flow_dict, alert_dict = persist_evaluation(db, evaluation, source="lab_aitm_proxy")

    await ws_manager.broadcast(
        {
            "event": "flow_evaluated",
            "source": "lab_aitm_proxy",
            "captured_demo_token": demo_token,
            "flow": flow_dict,
            "alert": alert_dict,
        }
    )

    payload = {
        "status": "aitm_relay_captured_demo",
        "mode": "AITM_REVERSE_PROXY",
        "username": username,
        "captured_session_token": demo_token,
        "measured_double_hop_latency_ms": measured_double_hop_ms,
        "risk_level": flow_dict["risk_level"],
        "predicted_threat": flow_dict["predicted_threat"],
        "risk_score": flow_dict["risk_score"],
        "top_contributing_features": flow_dict["top_contributing_features"],
        "evaluation": flow_dict,
        "alert": alert_dict,
    }

    if _wants_json(request):
        return JSONResponse(content=payload)

    reasons_li = "".join(
        f"<li><strong>{html.escape(item['feature'])}</strong>: {html.escape(item['explanation'])}</li>"
        for item in flow_dict["top_contributing_features"]
    )
    return HTMLResponse(
        content=f"""<!DOCTYPE html><html lang="es"><body style="font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:40px;">
        <div style="max-width:620px;margin:auto;background:#1e293b;padding:24px;border-radius:12px;border:2px solid #ef4444;">
        <div style="color:#fca5a5;font-size:12px;font-weight:700;letter-spacing:0.06em;">ENTORNO DE LABORATORIO CONTROLADO - DETECCIÓN EN VIVO</div>
        <h2 style="color:#f87171;margin:8px 0 12px;">Proxy Inverso AiTM Interceptado Pasivamente</h2>
        <p>Token ficticio capturado por el proxy demo: <code>{html.escape(demo_token)}</code></p>
        <p>Latencia real de doble salto medida: <strong>{measured_double_hop_ms} ms</strong> | Redirecciones: <strong>5</strong></p>
        <p>Veredicto CIPHERTRACE AI: <strong>{flow_dict['predicted_threat']}</strong> | Riesgo: <strong>{flow_dict['risk_level']}</strong> ({flow_dict['risk_score']:.4f})</p>
        <h4>Explicabilidad (XAI):</h4>
        <ul>{reasons_li}</ul>
        <p><a href="/lab/aitm-proxy" style="color:#38bdf8;">Volver al laboratorio AiTM</a></p>
        </div></body></html>"""
    )
