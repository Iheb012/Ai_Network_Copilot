# detection/evaluation.py
# Évaluation approfondie du modèle Isolation Forest

import sqlite3
import pandas as pd
import joblib
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

CHEMIN_MODELE = "../detection/model.pkl"

def charger_donnees():
    """Charge les données depuis la base SQLite"""
    connexion = sqlite3.connect("../data/network.db")
    df = pd.read_sql("""
        SELECT latency, error_rate, traffic, is_anomaly 
        FROM network_metrics 
        ORDER BY ts ASC
    """, connexion)
    connexion.close()
    return df

def evaluer_modele_complet():
    """
    Évaluation complète et professionnelle du modèle
    """
    print("=" * 60)
    print(" ÉVALUATION COMPLÈTE DU MODÈLE")
    print("=" * 60)
    
    # Charger les données et le modèle
    df = charger_donnees()
    modele = joblib.load(CHEMIN_MODELE)
    
    # Prédictions du modèle ML
    X = df[["latency", "error_rate", "traffic"]]
    predictions = modele.predict(X)
    df["prediction_ml"] = (predictions == -1).astype(int)
    
    # Vraies valeurs
    y_vrai = df["is_anomaly"]
    y_pred = df["prediction_ml"]
    
    # ---- Métriques de base ----
    vp = ((y_pred == 1) & (y_vrai == 1)).sum()
    vn = ((y_pred == 0) & (y_vrai == 0)).sum()
    fp = ((y_pred == 1) & (y_vrai == 0)).sum()
    fn = ((y_pred == 0) & (y_vrai == 1)).sum()
    
    print(f"\n MATRICE DE CONFUSION :")
    print(f"{'':20} Prédit Normal  Prédit Anomalie")
    print(f"{'Vrai Normal':20} {vn:12}  {fp:12}")
    print(f"{'Vrai Anomalie':20} {fn:12}  {vp:12}")
    
    # ---- Métriques professionnelles ----
    precision  = precision_score(y_vrai, y_pred)
    recall     = recall_score(y_vrai, y_pred)
    f1         = f1_score(y_vrai, y_pred)
    accuracy   = (vp + vn) / len(df)
    
    print(f"\n MÉTRIQUES DE PERFORMANCE :")
    print(f"   Précision globale (Accuracy) : {round(accuracy * 100, 2)}%")
    print(f"   Precision                    : {round(precision * 100, 2)}%")
    print(f"     → Sur toutes les alertes déclenchées,")
    print(f"       {round(precision * 100, 2)}% étaient de vraies anomalies")
    print(f"   Recall                       : {round(recall * 100, 2)}%")
    print(f"     → Sur toutes les vraies anomalies,")
    print(f"       {round(recall * 100, 2)}% ont été détectées")
    print(f"   F1-Score                     : {round(f1 * 100, 2)}%")
    print(f"     → Score global du modèle")
    
    # ---- Analyse par seuil ----
    print(f"\n ANALYSE DES ERREURS :")
    
    # Regarder les faux négatifs (anomalies manquées)
    faux_negatifs_df = df[(df["prediction_ml"] == 0) & (df["is_anomaly"] == 1)]
    if len(faux_negatifs_df) > 0:
        print(f"\n Anomalies manquées ({len(faux_negatifs_df)}) :")
        print(f"   Latence moyenne  : {round(faux_negatifs_df['latency'].mean(), 2)} ms")
        print(f"   Erreurs moyennes : {round(faux_negatifs_df['error_rate'].mean(), 2)} %")
        print(f"   → Ces anomalies sont proches des valeurs normales")
    
    # Regarder les faux positifs (fausses alertes)
    faux_positifs_df = df[(df["prediction_ml"] == 1) & (df["is_anomaly"] == 0)]
    if len(faux_positifs_df) > 0:
        print(f"\n  Fausses alertes ({len(faux_positifs_df)}) :")
        print(f"   Latence moyenne  : {round(faux_positifs_df['latency'].mean(), 2)} ms")
        print(f"   Erreurs moyennes : {round(faux_positifs_df['error_rate'].mean(), 2)} %")
        print(f"   → Ces mesures normales ressemblaient à des anomalies")
    
    # ---- Conclusion ----
    print(f"\n{'=' * 60}")
    print(f" CONCLUSION :")
    if f1 >= 0.95:
        print(f"   Le modèle est EXCELLENT (F1 = {round(f1*100, 2)}%)")
        print(f"   Il peut être utilisé en production !")
    elif f1 >= 0.85:
        print(f"   Le modèle est BON (F1 = {round(f1*100, 2)}%)")
        print(f"   Quelques ajustements seraient bénéfiques")
    else:
        print(f"   Le modèle nécessite des améliorations (F1 = {round(f1*100, 2)}%)")

if __name__ == "__main__":
    evaluer_modele_complet()