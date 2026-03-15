"""
Utilidades compartidas para generacion de informes HTML.
Badges, colores y helpers visuales reutilizables.
"""

from __future__ import annotations

# ── Colores por herramienta RMM ──────────────────────────────────────────────

RMM_COLORS: dict[str, str] = {
    "AnyDesk":                "#c0392b",   # Red
    "TeamViewer":             "#2980b9",   # Blue
    "ScreenConnect":          "#27ae60",   # Green
    "Chrome Remote Desktop":  "#8e44ad",   # Purple
    "Splashtop":              "#d68910",   # Orange
    "RustDesk":               "#1abc9c",   # Teal
}

# ── Badges HTML ──────────────────────────────────────────────────────────────


def rmm_badge(rmm_name: str) -> str:
    """Genera un badge HTML coloreado para un tipo de RMM."""
    color = RMM_COLORS.get(rmm_name, "#7a9b9b")
    return (
        f'<span style="background:{color}18;color:{color};border:1px solid {color};'
        f'border-radius:12px;padding:.15rem .6rem;font-size:.72rem;font-weight:700;'
        f'white-space:nowrap">{rmm_name}</span>'
    )


def risk_badge(level: str) -> str:
    """Genera un badge HTML para un nivel de riesgo."""
    RBADGE_BG = {
        "CRÍTICO": "#fde8e8", "ALTO": "#fef5e4",
        "MEDIO": "#fefae4", "BAJO": "#e8f5ee",
    }
    RBADGE_FG = {
        "CRÍTICO": "#c0392b", "ALTO": "#d68910",
        "MEDIO": "#9a7a10", "BAJO": "#1a7a47",
    }
    bg = RBADGE_BG.get(level, "#e8f5ee")
    fg = RBADGE_FG.get(level, "#1a7a47")
    return (
        f'<span style="background:{bg};color:{fg};border-radius:20px;'
        f'padding:.2rem .65rem;font-size:.75rem;font-weight:700;'
        f'border:1px solid currentColor">{level}</span>'
    )


def proximity_badge(label: str) -> str:
    """Genera un badge HTML para proximidad al incidente."""
    PROX_COLORS = {
        "CRÍTICO (±24h)": ("#fde8e8", "#c0392b"),
        "ALTO (±3d)":     ("#fef5e4", "#d68910"),
        "MEDIO (±7d)":    ("#fefae4", "#9a7a10"),
        "Fuera de ventana": ("#f0f4f4", "#7a9b9b"),
    }
    bg, fg = PROX_COLORS.get(label, ("#f0f4f4", "#7a9b9b"))
    return (
        f'<span style="background:{bg};color:{fg};border-radius:12px;'
        f'padding:.15rem .55rem;font-size:.72rem;font-weight:700;'
        f'border:1px solid {fg}44">{label}</span>'
    )
