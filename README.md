🛡️ Vigilant-X

Autonomous Threat Intelligence & Active Incident Response Engine

Un outil CLI défensif et interactif d'analyse forensique de logs SSH avec contre-mesures actives en temps réel.

Fonctionnalités • Installation • Utilisation • Architecture • Auteur

📌 Présentation

Vigilant-X est une solution de sécurité défensive conçue pour automatiser la détection des attaques par force brute (ex: échecs de connexion SSH), enrichir la menace via de la Threat Intelligence géolocalisée, et exécuter des contre-mesures d'isolement au niveau du noyau Linux (iptables).

Développé dans une approche SecOps & Interactive Incident Response, il permet à un opérateur de sécurité d'analyser rapidement des journaux d'événements et d'isoler manuellement ou en masse les adresses IP malveillantes.

✨ Fonctionnalités

🔍 Analyse Forensique Hôte : Parsing haute performance des tentatives de connexion SSH infructueuses (Invalid user / Failed password).

⚡ Regex Durcie (ReDoS Anti-Pattern) : Expression régulière optimisée pour éviter les vulnérabilités de déni de service sur des logs à forte volumétrie.

🌐 Threat Intel & Geolocation : Consultation dynamique via API REST (pays, ville, ISP/ASN) avec filtrage strict des réseaux privés (RFC 1918) et boucle locale.

🎯 Réponse aux Incidents Interactive : Interface de décision permettant à l'opérateur de bloquer des cibles ciblées (1 3), la totalité des menaces (all), ou d'ignorer.

🧱 Défense Active (Active Mitigation) : Application instantanée de règles de filtrage réseau iptables -j DROP sans dépendances externes tierces.

📄 Exportation de Rapports : Génération de rapports d'audit structurés au format JSON ou CSV (-o / --output).

🧪 Environnement de Test Intégré : Fourni avec un dataset de simulation (test.log) de 300+ lignes pour valider le comportement sans impacter vos logs réels.

🛠️ Installation

Prérequis

Système d'exploitation : Linux (Kali Linux, Ubuntu, Debian, RHEL)

Python 3.8+

Privilèges sudo (nécessaires pour l'application des règles iptables)

Cloner le projet & Installez les dépendances

git clone https://github.com/saadobr/Vigilant-X.git
cd Vigilant-X
pip3 install colorama requests


🚀 Utilisation

1. Test immédiat (avec le log de démonstration)

sudo python3 Vigilant-X.py test.log


2. Options et Commandes Avancées

# Modifier le seuil de déclenchement (ex: alerter à partir de 5 échecs)
sudo python3 Vigilant-X.py test.log -t 5

# Exporter les résultats au format JSON
sudo python3 Vigilant-X.py test.log -o report.json

# Exporter les résultats au format CSV
sudo python3 Vigilant-X.py test.log -o report.csv

# Afficher le menu d'aide
python3 Vigilant-X.py --help


🖥️ Flux d'Exécution

  ╔═══════════════════════════════════════════════════════════════╗
  ║                     V I G I L A N T - X                       ║
  ║        Autonomous Threat Intelligence & Log Forensics         ║
  ╚═══════════════════════════════════════════════════════════════╝

  [!] Engine Mode : Production Defensive Parser (Native Iptables Defense)
  [+] Lead Operator : s4yem

[✔] Ingesting log telemetry (test.log) - COMPLETE
[✔] Parsing failure counters & threshold filters - COMPLETE

===================== INCIDENT REPORT =====================

[1] HIGH SEVERITY ALERT: Hostile IP Detected -> 185.220.101.5
    ├── Failed Login Count : 93
    └── Threat Intel Data  : Country: DE | City: Berlin | ISP: AS60729

=================== METRICS & FORENSICS ===================
  ├── Total Log Lines Processed : 423
  ├── Unique IPs Identified     : 4
  └── Threshold Trigger Applied : >= 3 attempts
============================================================

[?] ACTIVE DEFENSE INTERFACE:
    - Enter space-separated numbers to block specific IPs (e.g., 1 3)
    - Type 'all' to block all detected threats instantly
    - Press Enter to skip and exit without blocking

[s4yem@Vigilant-X] Select action -> 1

[*] Applying counter-measure for target [1]...
[+] ACTIVE DEFENSE SUCCESS: IP 185.220.101.5 dropped via iptables.


🔒 Architecture & Sécurité

Protection contre le Path Traversal : Validation via os.path.isfile empêchant la lecture non autorisée de dossiers système.

Principe de Séparation des Privilèges : Exécution explicite des appels système via des listes d'arguments ciblées (subprocess.run), empêchant toute injection de commande shell.

Réseau Furtif : Blocage configuré sur DROP au lieu de REJECT, assurant un isolement complet sans réponse réseau envers les attaquants.

📁 Structure du Projet

Vigilant-X/
├── Vigilant-X.py   # Code source principal
├── test.log        # Jeu de données de test (300+ lignes)
└── README.md       # Documentation GitHub


👤 Auteur

s4yem

GitHub : @saadobr

Domaine : Cybersecurity / SecOps & Defensive Engineering

Projet développé à des fins éducatives et de présentation de portfolio en cybersécurité.
