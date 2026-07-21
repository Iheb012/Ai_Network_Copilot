# collector/lire_donnees.py
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'network.db')

def connecter():
    """Retourne une connexion à la base de données"""
    return sqlite3.connect(DB_PATH)

def lire_toutes_les_donnees():
    """Affiche toutes les données"""
    conn = connecter()
    curseur = conn.cursor()
    
    curseur.execute("""
        SELECT * FROM network_metrics 
        ORDER BY ts DESC 
        LIMIT 10
    """)
    lignes = curseur.fetchall()
    conn.close()
    
    print("=" * 60)
    print("📊 10 DERNIÈRES MESURES :")
    print("=" * 60)
    for ligne in lignes:
        print(f"  ID:{ligne[0]} | {ligne[2]:20} | "
              f"Latence:{ligne[3]:7} ms | "
              f"Erreurs:{ligne[4]:5} % | "
              f"{'🔴 ANOMALIE' if ligne[6] else '🟢 Normal'}")

def lire_par_hote(hote):
    """Affiche les données d'un hôte spécifique"""
    conn = connecter()
    curseur = conn.cursor()
    
    curseur.execute("""
        SELECT * FROM network_metrics
        WHERE host = ?
        ORDER BY ts DESC
        LIMIT 5
    """, (hote,))
    lignes = curseur.fetchall()
    conn.close()
    
    print(f"\n📡 5 DERNIÈRES MESURES DE {hote} :")
    print("-" * 60)
    for ligne in lignes:
        print(f"  {ligne[1]} | "
              f"Latence:{ligne[3]:7} ms | "
              f"Erreurs:{ligne[4]:5} % | "
              f"{'🔴 ANOMALIE' if ligne[6] else '🟢 Normal'}")

def lire_anomalies():
    """Affiche uniquement les anomalies"""
    conn = connecter()
    curseur = conn.cursor()
    
    curseur.execute("""
        SELECT * FROM network_metrics
        WHERE is_anomaly = 1
        ORDER BY ts DESC
    """)
    lignes = curseur.fetchall()
    conn.close()
    
    print(f"\n🔴 TOUTES LES ANOMALIES DÉTECTÉES : ({len(lignes)} au total)")
    print("-" * 60)
    for ligne in lignes:
        print(f"  {ligne[1]} | "
              f"Host:{ligne[2]:20} | "
              f"Latence:{ligne[3]:7} ms | "
              f"Erreurs:{ligne[4]:5} %")

def statistiques():
    """Affiche des statistiques générales"""
    conn = connecter()
    curseur = conn.cursor()
    
    # Statistiques globales
    curseur.execute("""
        SELECT 
            COUNT(*)                    as total,
            SUM(is_anomaly)             as anomalies,
            ROUND(AVG(latency), 2)      as latence_moyenne,
            ROUND(MAX(latency), 2)      as latence_max,
            ROUND(AVG(error_rate), 2)   as erreurs_moyennes
        FROM network_metrics
    """)
    stats = curseur.fetchone()
    conn.close()
    
    print("\n STATISTIQUES GÉNÉRALES :")
    print("-" * 60)
    print(f"  Total mesures      : {stats[0]}")
    print(f"  Total anomalies    : {stats[1]}")
    print(f"  Latence moyenne    : {stats[2]} ms")
    print(f"  Latence maximale   : {stats[3]} ms")
    print(f"  Erreurs moyennes   : {stats[4]} %")

# Programme principal
if __name__ == "__main__":
    lire_toutes_les_donnees()
    lire_par_hote("routeur-principal")
    lire_par_hote("serveur-web")
    lire_par_hote("switch-bureau")
    lire_anomalies()
    statistiques()