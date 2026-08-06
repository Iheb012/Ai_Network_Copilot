# detection/rules.py
# Détection ET identification des causes par règles métier

SEUILS = {
    "latency"    : 100,   # ms
    "error_rate" : 5,     # %
    "traffic_sat": 90,    # % saturation
    "timeout"    : 900    # ms = machine inaccessible
}

def identifier_cause(latency, error_rate, traffic):
    """
    Identifie la cause probable d'une anomalie
    selon la combinaison des valeurs mesurées.

    NOTE (home-LAN reality): the collector measures ping latency only, so
    error_rate/traffic are almost always 0. The multi-metric causes below are
    therefore only reachable when those signals actually carry data; otherwise
    we fall back to latency-based causes instead of "inconnu".
    """
    # Machine inaccessible / câble / interface
    if latency >= SEUILS["timeout"]:
        if traffic == 0 or traffic < 1:
            return "machine_inaccessible_ou_cable"
        return "interface_desactivee"

    # Multi-metric causes — only when we actually have error/traffic signals
    if error_rate > 0 or traffic > 0:
        # Panne WAN
        if latency > 400 and traffic < 10 and error_rate > 50:
            return "panne_wan"
        # Défaillance équipement réseau
        if latency > 200 and error_rate > 50 and traffic < 15:
            return "defaillance_equipement"
        # Pare-feu bloquant
        if error_rate > 40 and latency < 250 and traffic < 50:
            return "parefeu_bloquant"
        # Perte de paquets
        if error_rate > 20 and latency < 200:
            return "perte_paquets"
        # Saturation bande passante
        if traffic >= SEUILS["traffic_sat"] and latency > 100:
            return "saturation_bande_passante"
        # Congestion réseau
        if traffic >= SEUILS["traffic_sat"] and latency > 80:
            return "congestion"
        # Problème DNS / IP / CPU-RAM (only with real error/traffic evidence)
        if latency > 300 and error_rate < 30 and traffic < 50:
            return "panne_dns"
        if latency > 200 and error_rate > 30 and traffic < 35:
            return "probleme_ip"
        if latency > 200 and error_rate < 20 and traffic > 20:
            return "cpu_ram_sature"

    # High latency with NO packet loss → weak Wi-Fi signal / interference.
    # Far more likely for wireless clients than a DNS fault.
    if latency > 300 and error_rate < 5:
        return "signal_wifi_faible"

    # Latence élevée seule
    if latency > SEUILS["latency"]:
        return "latence_elevee"

    # Erreurs élevées seules
    if error_rate > SEUILS["error_rate"]:
        return "erreurs_elevees"

    # ML-only anomaly (no rule threshold crossed) → relative spike from the
    # device's own baseline that the rules missed.
    if latency > 0:
        return "latence_anormale"

    return "inconnu"

# Description lisible de chaque cause
DESCRIPTIONS_CAUSES = {
    "machine_inaccessible_ou_cable" : "Machine inaccessible ou câble débranché",
    "interface_desactivee"          : "Interface réseau désactivée ou défectueuse",
    "panne_wan"                     : "Défaillance du lien WAN / Internet",
    "defaillance_equipement"        : "Défaillance routeur ou switch",
    "parefeu_bloquant"              : "Pare-feu bloquant les communications",
    "perte_paquets"                 : "Perte de paquets réseau",
    "saturation_bande_passante"     : "Saturation de la bande passante",
    "congestion"                    : "Congestion / trafic réseau important",
    "panne_dns"                     : "Panne ou mauvaise configuration DNS",
    "probleme_ip"                   : "Problème de configuration IP ou passerelle",
    "cpu_ram_sature"                : "Forte utilisation CPU/RAM sur le serveur",
    "latence_elevee"                : "Latence réseau élevée",
    "erreurs_elevees"               : "Taux d'erreurs réseau élevé",
    "signal_wifi_faible"            : "Signal Wi-Fi faible ou interférences",
    "latence_anormale"              : "Latence anormale par rapport à la normale",
    "inconnu"                       : "Cause indéterminée",
}

# Conseils de diagnostic pour chaque cause
CONSEILS_CAUSES = {
    "machine_inaccessible_ou_cable" : "ping + arp -a + vérifier physiquement le câble",
    "interface_desactivee"          : "ipconfig /all + netsh interface set interface enable",
    "panne_wan"                     : "ping 8.8.8.8 + tracert + contacter le fournisseur",
    "defaillance_equipement"        : "Vérifier les logs équipement + redémarrer",
    "parefeu_bloquant"              : "telnet sur le port concerné + vérifier règles pare-feu",
    "perte_paquets"                 : "ping -n 100 + pathping + vérifier les câbles",
    "saturation_bande_passante"     : "Identifier gros consommateurs + appliquer QoS",
    "congestion"                    : "tracert + identifier flux + appliquer QoS",
    "panne_dns"                     : "nslookup + ipconfig /flushdns + changer DNS",
    "probleme_ip"                   : "ipconfig /all + vérifier passerelle + DHCP",
    "cpu_ram_sature"                : "tasklist (Windows) ou top (Linux) + redémarrer service",
    "latence_elevee"                : "ping + tracert + pathping",
    "erreurs_elevees"               : "ping -n 100 + vérifier câbles et équipements",
    "signal_wifi_faible"            : "Rapprocher l'appareil du routeur / changer de canal Wi-Fi / vérifier le signal",
    "latence_anormale"              : "Comparer avec la latence habituelle + vérifier le Wi-Fi ou l'activité de l'appareil",
    "inconnu"                       : "ping + tracert + ipconfig /all",
}

def detecter_anomalie_par_regles(latency, error_rate, traffic=0):
    """
    Détecte si une mesure est une anomalie
    Retourne True si anomalie, False si normal
    """
    return (
        latency    > SEUILS["latency"] or
        error_rate > SEUILS["error_rate"]
    )

def detail_detection(latency, error_rate, traffic=0):
    """
    Détection complète avec identification de la cause
    """
    est_anomalie = detecter_anomalie_par_regles(
        latency, error_rate, traffic
    )
    
    if not est_anomalie:
        return {
            "is_anomaly"  : False,
            "cause"       : "normal",
            "description" : "Aucune anomalie détectée",
            "conseil"     : "Aucune action requise",
            "raisons"     : ["Toutes les métriques sont normales"]
        }
    
    # Identifier la cause
    cause = identifier_cause(latency, error_rate, traffic)
    
    # Construire les raisons
    raisons = []
    if latency > SEUILS["latency"]:
        raisons.append(
            f"Latence élevée ({latency} ms > {SEUILS['latency']} ms)"
        )
    if error_rate > SEUILS["error_rate"]:
        raisons.append(
            f"Taux d'erreurs élevé ({error_rate}% > {SEUILS['error_rate']}%)"
        )
    if latency >= SEUILS["timeout"]:
        raisons.append(
            f"Timeout détecté ({latency} ms) — machine probablement inaccessible"
        )
    
    return {
        "is_anomaly"  : True,
        "cause"       : cause,
        "description" : DESCRIPTIONS_CAUSES.get(cause, cause),
        "conseil"     : CONSEILS_CAUSES.get(cause, "Diagnostic manuel requis"),
        "raisons"     : raisons
    }

def detecter_anomalie_seuils_adaptatifs(latency, error_rate, host=None):
    """
    Adaptive threshold detection — used by the simulator.
    Detects anomalies using static rules (per-host adaptive not yet implemented).
    Returns True if anomaly, False if normal.
    """
    return detecter_anomalie_par_regles(latency, error_rate, 0)

# Test direct
if __name__ == "__main__":
    print("=" * 60)
    print(" TEST DES RÈGLES AVEC IDENTIFICATION DES CAUSES")
    print("=" * 60)
    
    cas_test = [
        {"latency": 25.0,   "error_rate": 0.5,  "traffic": 45.0,  "nom": "Normal"},
        {"latency": 999.0,  "error_rate": 98.0, "traffic": 0.0,   "nom": "Machine inaccessible"},
        {"latency": 190.0,  "error_rate": 4.0,  "traffic": 97.0,  "nom": "Congestion"},
        {"latency": 120.0,  "error_rate": 35.0, "traffic": 16.0,  "nom": "Perte de paquets"},
        {"latency": 450.0,  "error_rate": 80.0, "traffic": 3.0,   "nom": "Panne WAN"},
        {"latency": 350.0,  "error_rate": 20.0, "traffic": 30.0,  "nom": "DNS"},
        {"latency": 250.0,  "error_rate": 55.0, "traffic": 10.0,  "nom": "Pare-feu"},
        {"latency": 300.0,  "error_rate": 15.0, "traffic": 40.0,  "nom": "CPU/RAM saturé"},
    ]
    
    for cas in cas_test:
        resultat = detail_detection(
            cas["latency"],
            cas["error_rate"],
            cas["traffic"]
        )
        statut = "🔴 ANOMALIE" if resultat["is_anomaly"] else "🟢 Normal"
        print(f"\n{cas['nom']} :")
        print(f"   Latence: {cas['latency']} ms | "
              f"Erreurs: {cas['error_rate']}% | "
              f"Trafic: {cas['traffic']} Mbps")
        print(f"   Résultat    : {statut}")
        if resultat["is_anomaly"]:
            print(f"   Cause       : {resultat['description']}")
            print(f"   Conseil     : {resultat['conseil']}")