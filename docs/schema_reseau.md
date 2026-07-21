# Schéma Réseau — AI Network Copilot

## Infrastructure complète

### Équipements
- R1  : Routeur Cisco 2911 (routeur principal)
- SW1 : Switch Cisco 2960-24TT (branche gauche)
- SW2 : Switch Cisco 2960-24TT (branche droite)
- PC1, PC2 : PCs branche gauche (réseau 192.168.1.x)
- PC3, PC4 : PCs branche droite (réseau 192.168.2.x)
- WEB_SERVER : Serveur web (192.168.1.x)
- DMZ_SERVER : Serveur DMZ (192.168.2.x)

### Adressage réseau
- Branche gauche (SW1) : 192.168.1.0/24
- Branche droite (SW2) : 192.168.2.0/24

## Branche simulée
On simule uniquement la branche gauche :
R1 → SW1 → PC1, PC2, WEB_SERVER

## Hôtes surveillés par notre simulateur
- R1         : routeur principal
- SW1        : switch branche gauche
- WEB_SERVER : serveur web 