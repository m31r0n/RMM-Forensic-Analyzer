from ..models.base import RMMSession, RMMType

RISK_LEVELS = [
    (7, "CRÍTICO"),
    (4, "ALTO"),
    (2, "MEDIO"),
    (0, "BAJO"),
]

def score_session(session: RMMSession) -> tuple[str, int, list[str]]:
    """Score a session regardless of RMM type. Returns (level, score, reasons)."""
    score = 0
    reasons = []

    # === Common rules (all RMMs) ===
    # File transfers
    if session.file_transfers >= 1:
        score += 3
        reasons.append(f"{session.file_transfers} transferencia(s) de archivo detectada(s)")

    # Elevated privileges
    if session.elevated:
        score += 3
        reasons.append("sesión con privilegios elevados detectada")

    # Large clipboard
    if session.clipboard_max_files > 100:
        score += 4
        reasons.append(f"portapapeles MASIVO ({session.clipboard_max_files} archivos) → exfiltración probable")
    elif session.clipboard_max_files > 20:
        score += 2
        reasons.append(f"portapapeles elevado ({session.clipboard_max_files} archivos simultáneos)")
    elif session.clipboard_max_files > 5:
        score += 1
        reasons.append(f"portapapeles con {session.clipboard_max_files} archivos")

    # Text transfers
    if session.text_transfers > 0:
        score += 1
        reasons.append(f"{session.text_transfers} transferencia(s) de texto → posible copia de credenciales")

    # === RMM-specific rules (from extras) ===
    score_rmm, reasons_rmm = _score_rmm_specific(session)
    score += score_rmm
    reasons.extend(reasons_rmm)

    # Determine level
    level = next(lvl for threshold, lvl in RISK_LEVELS if score >= threshold)
    return level, score, reasons


def _score_rmm_specific(session: RMMSession) -> tuple[int, list[str]]:
    """Apply RMM-specific scoring rules based on extras."""
    if session.rmm_type == RMMType.ANYDESK:
        return _score_anydesk(session)
    elif session.rmm_type == RMMType.TEAMVIEWER:
        return _score_teamviewer(session)
    elif session.rmm_type == RMMType.SCREENCONNECT:
        return _score_screenconnect(session)
    return 0, []


def _score_anydesk(session: RMMSession) -> tuple[int, list[str]]:
    """AnyDesk-specific risk scoring using extras."""
    score = 0
    reasons = []
    extras = session.extras

    # Winlogon switches
    wl = extras.get("winlogon_switches", 0)
    if wl >= 5:
        score += 3
        reasons.append(f"{wl} cambios a Winlogon → acceso repetido a credenciales")
    elif wl >= 2:
        score += 2
        reasons.append(f"{wl} cambios a pantalla de inicio de sesión (Winlogon)")
    elif wl >= 1:
        score += 1
        reasons.append(f"{wl} cambio a Winlogon durante sesión activa")

    # Minimized (covert)
    if extras.get("minimized", False):
        score += 1
        reasons.append("sesión iniciada con ventana minimizada (modo encubierto)")

    # No password
    if extras.get("no_password", False):
        score += 1
        reasons.append("perfil sin contraseña (hasPw: N) → sin protección adicional")

    # TCP tunnel
    if extras.get("tcp_tunnel_active", False):
        score += 1
        reasons.append("túnel TCP activo → posible pivoting de red")

    # Risky permissions
    perms = extras.get("perms", {})
    if isinstance(perms, dict):
        if perms.get("sysinfo", {}).get("enabled", False):
            score += 1
            reasons.append("permiso 'sysinfo' habilitado → acceso a info del sistema")
        if perms.get("file_manager", {}).get("enabled", False):
            score += 1
            reasons.append("permiso 'file_manager' habilitado remotamente")

    return score, reasons


def _score_teamviewer(session: RMMSession) -> tuple[int, list[str]]:
    """TeamViewer-specific risk scoring."""
    score = 0
    reasons = []
    extras = session.extras

    # Unattended access
    if extras.get("unattended", False):
        score += 1
        reasons.append("acceso desatendido (sin usuario presente)")

    # Connection type
    conn_type = extras.get("connection_type", "")
    if "FileTransfer" in conn_type:
        score += 2
        reasons.append("sesión de tipo FileTransfer (transferencia directa)")

    return score, reasons


def _score_screenconnect(session: RMMSession) -> tuple[int, list[str]]:
    """ScreenConnect-specific risk scoring."""
    score = 0
    reasons = []
    extras = session.extras

    if extras.get("commands_executed", 0) > 0:
        score += 2
        reasons.append(f"{extras['commands_executed']} comando(s) ejecutado(s) remotamente")

    return score, reasons


def score_all(sessions: list[RMMSession]) -> None:
    """Apply scoring to all sessions in-place."""
    for s in sessions:
        s.risk, s.risk_score, s.risk_reasons = score_session(s)
