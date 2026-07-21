# detection/application_regles.py
# Applique nos règles de détection sur toutes les données de la base
# et compare avec les anomalies déjà marquées par le simulateur

import sqlite3
import sys
sys.path.append("..")  # pour pouvoir importer depuis le dossier collector si besoin
from rules import detecter_anomalie_par_regles

def charger_donnees():
    """Charge toutes les mesures depuis la base de données"""
    connexion = sqlite3.connect("../data/network.db")
    curseur = connexion.cursor()
    curseur.execute("SELECT id, ts, host, latency, error_rate, is_anomaly FROM network_metrics")
    lignes = curseur.fetchall()
    connexion.close()
    return lignes

def evaluer_regles():
    """
    Compare les résultats de nos règles avec les vraies anomalies
    (celles injectées par le simulateur, qu'on connaît déjà)
    """
    lignes = charger_donnees()
    
    vrais_positifs  = 0  # règle dit anomalie, et c'est vraiment une anomalie
    faux_positifs   = 0  # règle dit anomalie, mais c'était normal
    vrais_negatifs  = 0  # règle dit normal, et c'était vraiment normal
    faux_negatifs   = 0  # règle dit normal, mais c'était une anomalie
    
    for ligne in lignes:
        id_, ts, host, latency, error_rate, vraie_anomalie = ligne
        
        # On applique notre règle
        regle_dit_anomalie = detecter_anomalie_par_regles(latency, error_rate)
        
        # On compare avec la vérité (is_anomaly du simulateur)
        if regle_dit_anomalie and vraie_anomalie:
            vrais_positifs += 1
        elif regle_dit_anomalie and not vraie_anomalie:
            faux_positifs += 1
        elif not regle_dit_anomalie and not vraie_anomalie:
            vrais_negatifs += 1
        elif not regle_dit_anomalie and vraie_anomalie:
            faux_negatifs += 1
    
    total = len(lignes)
    
    print("=" * 60)
    print(" ÉVALUATION DES RÈGLES SUR LES DONNÉES RÉELLES")
    print("=" * 60)
    print(f"\nTotal de mesures analysées : {total}")
    print(f"\n✅ Vrais positifs  (anomalie détectée correctement) : {vrais_positifs}")
    print(f"✅ Vrais négatifs  (normal détecté correctement)     : {vrais_negatifs}")
    print(f"❌ Faux positifs   (fausse alerte)                   : {faux_positifs}")
    print(f"❌ Faux négatifs   (anomalie manquée)                : {faux_negatifs}")
    
    # Calcul de la précision globale
    precision = round((vrais_positifs + vrais_negatifs) / total * 100, 2)
    print(f"\n Précision globale des règles : {precision}%")

if __name__ == "__main__":
    evaluer_regles()