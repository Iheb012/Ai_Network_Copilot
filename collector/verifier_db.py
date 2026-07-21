# collector/verifier_db.py
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'network.db')

def verifier_base():
    """
    Lit et affiche les données dans la base de données
    """
    connexion = sqlite3.connect(DB_PATH)
    curseur   = connexion.cursor()
    
    # On vérifie quelles tables existent
    print("=" * 60)
    print(" TABLES DANS LA BASE DE DONNÉES :")
    print("=" * 60)
    
    curseur.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table'
    """)
    tables = curseur.fetchall()
    
    for table in tables:
        nom_table = table[0]
        print(f"\n Table : {nom_table}")
        
        # Compter les lignes
        curseur.execute(f"SELECT COUNT(*) FROM {nom_table}")
        nombre = curseur.fetchone()[0]
        print(f"   Nombre de lignes : {nombre}")
        
        # Afficher les 5 dernières lignes
        if nombre > 0:
            print(f"   5 dernières lignes :")
            curseur.execute(f"""
                SELECT * FROM {nom_table} 
                ORDER BY rowid DESC 
                LIMIT 5
            """)
            lignes = curseur.fetchall()
            for ligne in lignes:
                print(f"   -> {ligne}")
    
    connexion.close()
    print("\n" + "=" * 60)

if __name__ == "__main__":
    verifier_base()