# api/detection_bridge.py
# Pont entre le module de détection (Personne A)
# et l'API FastAPI (Personne B)


import sys
import os
import datetime
import sqlite3
import time

# Ajouter le dossier detection au chemin
DOSSIER_PROJET = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(DOSSIER_PROJET, "detection"))

from detecteur import detecter, detecter_lot, charger_modele

# Charger le modèle une seule fois au démarrage
_modele = None

def get_modele():
    """Charge le modèle ML une seule fois"""
    global _modele
    if _modele is None:
        _modele = charger_modele()
    return _modele


# ── TTL cache ─────────────────────────────────────────────────────────────
# The API's three WebSocket streams + REST endpoints all call detecter_lot()
# (a SQLite read + Isolation-Forest predict). Recomputing on every request is
# what makes the app feel heavy, so we share ONE result per time window.
_CACHE_TTL_SECONDS = 5.0
_cache = {}

def _cached(key, producer):
    now = time.monotonic()
    entry = _cache.get(key)
    if entry is not None and now - entry[0] < _CACHE_TTL_SECONDS:
        return entry[1]
    value = producer()
    _cache[key] = (now, value)
    return value


def get_alerts_with_causes(limit: int = 50) -> list:
    """
    Remplace get_alerts() de database.py — alertes avec causes ML.
    Résultat partagé via cache TTL (5s) pour ne pas re-prédire à chaque requête.
    """
    return _cached(("alerts", limit), lambda: _build_alerts(limit))


def _build_alerts(limit):
    resultats = detecter_lot(limit=limit * 3)  # on prend plus pour filtrer

    alertes = []
    for r in resultats:
        if r["is_anomaly"]:
            alertes.append({
                "ts"             : r["ts"],
                "host"           : r["host"],
                "reason"         : r["description"],  # cause réelle !
                "conseil"        : r["conseil"],
                "methode"        : r["methode"],
                "score_confiance": r["score_confiance"],
                "latency"        : r["latency"],
                "error_rate"     : r["error_rate"],
                "traffic"        : r["traffic"]
            })

            if len(alertes) >= limit:
                break

    return alertes

def get_metrics_with_detection(limit: int = 100) -> list:
    """
    Remplace get_latest_metrics() de database.py — métriques avec détection ML.
    Résultat partagé via cache TTL (5s).
    """
    return _cached(("metrics", limit), lambda: _build_metrics(limit))


def _build_metrics(limit):
    resultats = detecter_lot(limit=limit)

    metrics = []
    for r in resultats:
        metrics.append({
            "ts"             : r["ts"],
            "host"           : r["host"],
            "latency"        : r["latency"],
            "error_rate"     : r["error_rate"],
            "traffic"        : r["traffic"],
            "is_anomaly"     : r["is_anomaly"],
            "cause"          : r["cause"],
            "description"    : r["description"],
            "conseil"        : r["conseil"],
            "score_confiance": r["score_confiance"]
        })

    return metrics

def analyser_metrique_temps_reel(latency, error_rate, traffic) -> dict:
    """
    Analyse UNE mesure en temps réel
    Utilisée par l'API pour les requêtes en direct
    """
    modele  = get_modele()
    resultat = detecter(latency, error_rate, traffic, modele)
    return resultat

# Test du pont
if __name__ == "__main__":
    print("=" * 60)
    print(" TEST DU PONT API ↔ DÉTECTION")
    print("=" * 60)
    
    print("\n1. Test get_alerts_with_causes() :")
    alertes = get_alerts_with_causes(limit=5)
    print(f"   {len(alertes)} alertes trouvées")
    for a in alertes[:3]:
        print(f"   🔴 {a['host']:12} → {a['reason']}")
        print(f"      Conseil : {a['conseil']}")
    
    print("\n2. Test get_metrics_with_detection() :")
    metrics = get_metrics_with_detection(limit=5)
    print(f"   {len(metrics)} métriques analysées")
    for m in metrics[:3]:
        statut = "🔴" if m["is_anomaly"] else "🟢"
        print(f"   {statut} {m['host']:12} | "
              f"Latence: {m['latency']} ms | "
              f"Cause: {m['description']}")
    
    print("\n3. Test analyser_metrique_temps_reel() :")
    r = analyser_metrique_temps_reel(999.0, 98.0, 0.0)
    print(f"   Machine inaccessible → {r['description']}")
    print(f"   Conseil : {r['conseil']}")
    
    print("\n Pont API ↔ Détection fonctionnel !")