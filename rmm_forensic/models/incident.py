"""Modelo de contexto de incidente para análisis forense contextual."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class IncidentContext:
    """
    Parámetros del incidente para análisis de proximidad temporal,
    clasificación por país y filtrado.
    """
    incident_date:    Optional[datetime] = None
    origin_country:   str = ""          # Código ISO 2 letras (MX, CO, AR, etc.)
    hostname_filter:  str = ""          # Filtrar por hostname específico
    user_filter:      str = ""          # Filtrar por usuario específico

    # Ventanas de análisis (días antes y después del incidente)
    window_critical_hours: int = 24     # ±24 horas
    window_high_days:      int = 3      # ±3 días
    window_medium_days:    int = 7      # ±7 días

    @property
    def has_incident_date(self) -> bool:
        return self.incident_date is not None

    @property
    def has_country(self) -> bool:
        return bool(self.origin_country)

    @property
    def window_24h(self) -> Optional[tuple[datetime, datetime]]:
        if not self.incident_date:
            return None
        delta = timedelta(hours=self.window_critical_hours)
        return (self.incident_date - delta, self.incident_date + delta)

    @property
    def window_3d(self) -> Optional[tuple[datetime, datetime]]:
        if not self.incident_date:
            return None
        delta = timedelta(days=self.window_high_days)
        return (self.incident_date - delta, self.incident_date + delta)

    @property
    def window_7d(self) -> Optional[tuple[datetime, datetime]]:
        if not self.incident_date:
            return None
        delta = timedelta(days=self.window_medium_days)
        return (self.incident_date - delta, self.incident_date + delta)

    def classify_proximity(self, dt: Optional[datetime]) -> str:
        """
        Clasifica la proximidad temporal de un evento respecto al incidente.
        Retorna: "CRÍTICO (±24h)", "ALTO (±3d)", "MEDIO (±7d)", "Fuera de ventana", ""
        """
        if not self.incident_date or not dt:
            return ""

        delta = abs((dt - self.incident_date).total_seconds())
        hours = delta / 3600

        if hours <= self.window_critical_hours:
            return "CRÍTICO (±24h)"
        elif hours <= self.window_high_days * 24:
            return "ALTO (±3d)"
        elif hours <= self.window_medium_days * 24:
            return "MEDIO (±7d)"
        else:
            return "Fuera de ventana"

    def proximity_hours(self, dt: Optional[datetime]) -> Optional[float]:
        """Retorna distancia en horas al incidente, o None."""
        if not self.incident_date or not dt:
            return None
        return abs((dt - self.incident_date).total_seconds()) / 3600

    def classify_country(self, country_code: str) -> str:
        """
        Clasifica la conexión según el país de origen configurado.
        Retorna: "Informativa" (mismo país), "Sospechosa" (extranjera), ""
        """
        if not self.origin_country or not country_code:
            return ""
        if country_code.upper() == self.origin_country.upper():
            return "Informativa"
        return "Sospechosa"
