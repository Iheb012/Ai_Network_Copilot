# collector/ping_collector.py
import os
import ping3
import sqlite3
import datetime
import time
from database import creer_base_de_donnees

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'network.db')

# Les adresses IP qu'on va pinguer
CIBLES = [
    "8.8.8.8",    # Google DNS
    "1.1.1.1",    # Cloudflare DNS
]

def collecter_ping():
    """
    Envoie un ping à chaque cible et retourne les résultats
    """
    resultats = []
    
    for ip in CIBLES:
        # On envoie le ping
        latence = ping3.ping(ip, timeout=2)
        
        # Si pas de réponse, latence = -1
        if latence is None:
            latence = -1
        else:
            # On convertit en millisecondes
            latence = latence * 1000
            
        # On note l'heure actuelle
        maintenant = datetime.datetime.now().isoformat()
        
        resultats.append({
            "ts"        : maintenant,
            "host"      : ip,
            "latency"   : round(latence, 2),
            "error_rate": 0,
            "traffic"   : 0,
            "is_anomaly": 0
        })
        
        print(f" Ping vers {ip} : {round(latence, 2)} ms")
    
    return resultats

def sauvegarder(resultats):
    """
    Sauvegarde les résultats dans la base de données
    """
    connexion = sqlite3.connect(DB_PATH)
    curseur   = connexion.cursor()
    
    for r in resultats:
        curseur.execute("""
            INSERT INTO network_metrics 
            (ts, host, latency, error_rate, traffic, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            r["ts"],
            r["host"],
            r["latency"],
            r["error_rate"],
            r["traffic"],
            r["is_anomaly"]
        ))
    
    connexion.commit()
    connexion.close()
    print("Données sauvegardées !\n")

# Programme principal
if __name__ == "__main__":
    # On crée la base de données si elle n'existe pas
    creer_base_de_donnees()
    
    print("Collecteur ping démarré...")
    print("Appuie sur Ctrl+C pour arrêter\n")
    
    # Boucle infinie : on collecte toutes les 5 secondes
    while True:
        resultats = collecter_ping()
        sauvegarder(resultats)
        print("Prochaine collecte dans 5 secondes...\n")
        time.sleep(5)