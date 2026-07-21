# Schéma de données — AI Network Copilot

## Source choisie : Simulateur Python

## Structure de la table `metrics`

| Colonne    | Type    | Description              |
|------------|---------|--------------------------|
| timestamp  | TEXT    | Date et heure            |
| latency    | REAL    | Latence en ms            |
| traffic    | REAL    | Trafic en Mbps           |
| error_rate | REAL    | Taux d'erreurs en %      |
| is_anomaly | INTEGER | 0 = normal, 1 = anomalie |

## Valeurs normales
- Latence : entre 5 et 40 ms
- Trafic : entre 0 et 100 Mbps
- Taux d'erreurs : entre 0 et 1 %

## Valeurs anormales (5% des cas)
- Latence : entre 80 et 200 ms
- Taux d'erreurs : entre 5 et 20 %