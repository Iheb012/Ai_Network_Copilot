# detection/ml_model.py
# Détection d'anomalies par Machine Learning (Isolation Forest)

import sqlite3
import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest

# Chemin où on sauvegarde le modèle entraîné
CHEMIN_MODELE = "../detection/model.pkl"

def charger_donnees():
    """
    Charge les données depuis la base SQLite
    et retourne un DataFrame Pandas propre
    """
    connexion = sqlite3.connect("../data/network.db")
    df = pd.read_sql("""
        SELECT latency, error_rate, traffic, is_anomaly 
        FROM network_metrics 
        ORDER BY ts ASC
    """, connexion)
    connexion.close()
    return df

def entrainer_modele():
    """
    Entraîne le modèle Isolation Forest sur les données
    et le sauvegarde dans un fichier .pkl
    """
    print("=" * 60)
    print(" ENTRAÎNEMENT DU MODÈLE ISOLATION FOREST")
    print("=" * 60)
    
    # Charger les données
    df = charger_donnees()
    print(f"\n Données chargées : {len(df)} mesures")
    
    # Calculer le vrai taux d'anomalies dans nos données
    vrai_taux = round(df["is_anomaly"].sum() / len(df), 3)
    print(f" Vrai taux d'anomalies dans les données : {vrai_taux*100}%")
    
    # On entraîne avec le vrai taux
    modele = IsolationForest(
        contamination = vrai_taux,
        random_state  = 42,
        n_estimators  = 100
    )
    
    # On entraîne sur les 3 métriques
    X = df[["latency", "error_rate", "traffic"]]
    modele.fit(X)
    print("✅ Modèle entraîné !")
    
    # On sauvegarde le modèle
    joblib.dump(modele, CHEMIN_MODELE)
    print(f" Modèle sauvegardé dans {CHEMIN_MODELE}")
    
    return modele, df

def evaluer_modele(modele, df):
    """
    Évalue le modèle sur nos données
    et compare avec les vraies anomalies du simulateur
    """
    print("\n" + "=" * 60)
    print(" ÉVALUATION DU MODÈLE")
    print("=" * 60)
    
    # On prédit sur toutes les données
    X = df[["latency", "error_rate", "traffic"]]
    predictions = modele.predict(X)
    
    # Isolation Forest retourne : -1 = anomalie, 1 = normal
    # On convertit en 0/1 pour comparer avec nos données
    df["prediction_ml"] = (predictions == -1).astype(int)
    
    # Comparaison avec les vraies anomalies
    vrais_positifs = ((df["prediction_ml"] == 1) & (df["is_anomaly"] == 1)).sum()
    faux_positifs  = ((df["prediction_ml"] == 1) & (df["is_anomaly"] == 0)).sum()
    vrais_negatifs = ((df["prediction_ml"] == 0) & (df["is_anomaly"] == 0)).sum()
    faux_negatifs  = ((df["prediction_ml"] == 0) & (df["is_anomaly"] == 1)).sum()
    
    total = len(df)
    
    print(f"\nTotal de mesures analysées : {total}")
    print(f"\n✅ Vrais positifs  (anomalie détectée correctement) : {vrais_positifs}")
    print(f"✅ Vrais négatifs  (normal détecté correctement)     : {vrais_negatifs}")
    print(f"❌ Faux positifs   (fausse alerte)                   : {faux_positifs}")
    print(f"❌ Faux négatifs   (anomalie manquée)                : {faux_negatifs}")
    
    precision = round((vrais_positifs + vrais_negatifs) / total * 100, 2)
    print(f"\n Précision du modèle ML : {precision}%")
    
    return df

def predire(latency, error_rate, traffic):
    """
    Prédit si UNE mesure est une anomalie
    Utilisée plus tard par le module de détection combiné
    """
    # Charger le modèle sauvegardé
    if not os.path.exists(CHEMIN_MODELE):
        print(" Modèle non trouvé ! Lance d'abord entrainer_modele()")
        return False
    
    modele = joblib.load(CHEMIN_MODELE)
    
    
    # Prédire avec un DataFrame pour éviter le warning
    import pandas as pd
    X = pd.DataFrame([[latency, error_rate, traffic]], 
                  columns=["latency", "error_rate", "traffic"])
    prediction = modele.predict(X)
    # -1 = anomalie, 1 = normal
    return prediction[0] == -1

# Programme principal
if __name__ == "__main__":
    # 1. Entraîner et sauvegarder le modèle
    modele, df = entrainer_modele()
    
    # 2. Évaluer le modèle
    df_resultat = evaluer_modele(modele, df)
    
    # 3. Test sur quelques exemples
    print("\n" + "=" * 60)
    print(" TESTS SUR DES EXEMPLES")
    print("=" * 60)
    
    exemples = [
        {"latency": 25.0,  "error_rate": 0.5,  "traffic": 45.0, "nom": "Cas normal"},
        {"latency": 150.0, "error_rate": 1.0,  "traffic": 90.0, "nom": "Latence élevée"},
        {"latency": 30.0,  "error_rate": 12.0, "traffic": 20.0, "nom": "Erreurs élevées"},
        {"latency": 95.0,  "error_rate": 4.5,  "traffic": 60.0, "nom": "Cas limite"},
    ]
    
    for ex in exemples:
        est_anomalie = predire(ex["latency"], ex["error_rate"], ex["traffic"])
        statut = "🔴 ANOMALIE" if est_anomalie else "🟢 Normal"
        print(f"\n{ex['nom']} :")
        print(f"   Latence: {ex['latency']} ms | Erreurs: {ex['error_rate']}% | Trafic: {ex['traffic']} Mbps")
        print(f"   Résultat ML : {statut}")