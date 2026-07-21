# collector/nettoyage_donnees.py
import os
import pandas as pd
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'network.db')

def charger_donnees():
    """
    Charge les données depuis SQLite vers un DataFrame Pandas
    """
    connexion = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM network_metrics ORDER BY ts ASC", connexion)
    connexion.close()
    
    print("=" * 60)
    print(" DONNÉES CHARGÉES :")
    print(f"   Lignes   : {len(df)}")
    print(f"   Colonnes : {list(df.columns)}")
    return df

def nettoyer_donnees(df):
    """
    Nettoie les données
    """
    print("\n" + "=" * 60)
    print(" NETTOYAGE :")
    print("=" * 60)
    
    nb_avant = len(df)
    
    # Supprimer les doublons
    df = df.drop_duplicates()
    print(f"1. Doublons supprimés      : {nb_avant - len(df)}")
    
    # Supprimer les lignes vides
    df = df.dropna()
    print(f"2. Lignes vides supprimées : {nb_avant - len(df)}")
    
    # Convertir timestamp en datetime
    df["ts"] = pd.to_datetime(df["ts"])
    print("3. Timestamp converti      : ")
    
    # Supprimer latences négatives
    df = df[df["latency"] >= 0]
    print("4. Latences négatives      : supprimées ")
    
    # Supprimer taux d'erreur impossibles
    df = df[(df["error_rate"] >= 0) & (df["error_rate"] <= 100)]
    print("5. Taux d'erreurs invalides: supprimés ")
    
    print(f"\n Données propres : {len(df)} lignes")
    return df

def analyser_donnees(df):
    """
    Analyse rapide des données propres
    """
    print("\n" + "=" * 60)
    print("📈 ANALYSE :")
    print("=" * 60)
    
    # Statistiques par hôte
    print("\nStatistiques par hôte :")
    stats = df.groupby("host").agg(
        mesures     = ("latency", "count"),
        latence_moy = ("latency", "mean"),
        latence_max = ("latency", "max"),
        erreurs_moy = ("error_rate", "mean"),
        anomalies   = ("is_anomaly", "sum")
    ).round(2)
    print(stats)
    
    # Résumé global
    total       = len(df)
    anomalies   = df["is_anomaly"].sum()
    pourcentage = round((anomalies / total) * 100, 2)
    
    print(f"\nRésumé global :")
    print(f"   Total mesures  : {total}")
    print(f"   Total anomalies: {anomalies} ({pourcentage}%)")
    print(f"   Latence moyenne: {round(df['latency'].mean(), 2)} ms")
    print(f"   Latence max    : {round(df['latency'].max(), 2)} ms")

# Programme principal
if __name__ == "__main__":
    df = charger_donnees()
    df_propre = nettoyer_donnees(df)
    analyser_donnees(df_propre)