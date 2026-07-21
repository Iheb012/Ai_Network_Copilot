# detection/exploration.py
# Analyse exploratoire des données réseau collectées

import pandas as pd
import sqlite3

def charger_donnees():
    """
    Charge toutes les données depuis la base SQLite
    """
    connexion = sqlite3.connect("../data/network.db")
    df = pd.read_sql("SELECT * FROM network_metrics ORDER BY ts ASC", connexion)
    connexion.close()
    
    # On convertit le timestamp en vrai format date
    df["ts"] = pd.to_datetime(df["ts"])
    
    return df

def vue_generale(df):
    """
    Donne une première vue d'ensemble des données
    """
    print("=" * 60)
    print(" VUE GÉNÉRALE")
    print("=" * 60)
    
    print(f"\nNombre total de mesures : {len(df)}")
    print(f"Période couverte        : {df['ts'].min()} → {df['ts'].max()}")
    print(f"Hôtes surveillés        : {df['host'].unique().tolist()}")
    print(f"Mesures par hôte        :")
    print(df["host"].value_counts())

def distribution_metriques(df):
    """
    Analyse la distribution de chaque métrique
    Distribution = comment les valeurs sont réparties (min, max, moyenne...)
    """
    print("\n" + "=" * 60)
    print(" DISTRIBUTION DES MÉTRIQUES")
    print("=" * 60)
    
    print("\nLatence (ms) :")
    print(df["latency"].describe().round(2))
    
    print("\nTrafic (Mbps) :")
    print(df["traffic"].describe().round(2))
    
    print("\nTaux d'erreurs (%) :")
    print(df["error_rate"].describe().round(2))

def comparaison_normal_anomalie(df):
    """
    Compare les statistiques entre situations normales et anomalies
    """
    print("\n" + "=" * 60)
    print(" NORMAL vs ANOMALIE")
    print("=" * 60)
    
    normal = df[df["is_anomaly"] == 0]
    anomalie = df[df["is_anomaly"] == 1]
    
    print(f"\nNombre de mesures normales  : {len(normal)}")
    print(f"Nombre de mesures anomalies : {len(anomalie)}")
    print(f"Pourcentage d'anomalies     : {round(len(anomalie)/len(df)*100, 2)}%")
    
    print("\nMoyennes en situation NORMALE :")
    print(f"   Latence    : {round(normal['latency'].mean(), 2)} ms")
    print(f"   Trafic     : {round(normal['traffic'].mean(), 2)} Mbps")
    print(f"   Erreurs    : {round(normal['error_rate'].mean(), 2)} %")
    
    print("\nMoyennes en situation ANOMALIE :")
    print(f"   Latence    : {round(anomalie['latency'].mean(), 2)} ms")
    print(f"   Trafic     : {round(anomalie['traffic'].mean(), 2)} Mbps")
    print(f"   Erreurs    : {round(anomalie['error_rate'].mean(), 2)} %")

def correlation_metriques(df):
    """
    Vérifie si les métriques sont liées entre elles
    Corrélation proche de 1 ou -1 = liées
    Corrélation proche de 0 = pas liées
    """
    print("\n" + "=" * 60)
    print(" CORRÉLATION ENTRE MÉTRIQUES")
    print("=" * 60)
    
    correlation = df[["latency", "traffic", "error_rate", "is_anomaly"]].corr().round(2)
    print(correlation)
    
    print("\n💡 Lecture : plus une valeur est proche de 1 ou -1, plus les 2 métriques sont liées")

def analyse_par_hote(df):
    """
    Compare le comportement de chaque hôte
    """
    print("\n" + "=" * 60)
    print("  ANALYSE PAR HÔTE")
    print("=" * 60)
    
    stats = df.groupby("host").agg(
        mesures      = ("latency", "count"),
        latence_moy  = ("latency", "mean"),
        latence_max  = ("latency", "max"),
        erreurs_moy  = ("error_rate", "mean"),
        anomalies    = ("is_anomaly", "sum")
    ).round(2)
    
    print(stats)

# Programme principal
if __name__ == "__main__":
    df = charger_donnees()
    
    vue_generale(df)
    distribution_metriques(df)
    comparaison_normal_anomalie(df)
    correlation_metriques(df)
    analyse_par_hote(df)