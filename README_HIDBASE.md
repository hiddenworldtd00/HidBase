# HIDBASE - Database Discovery & Analysis Tool

**Développé par HiddenWorld** - Informaticien Tchadien 🇹🇩

---

## Description

HIDBASE est un outil Python avancé en une seule page qui permet de découvrir, analyser et cartographier les bases de données potentielles d'un site web. Il effectue une reconnaissance approfondie pour identifier les technologies de base de données, les points d'accès API, les fuites d'informations et les vulnérabilités potentielles.

## Fonctionnalités Détaillées

### 1. Analyse DNS & Infrastructure
- Résolution DNS complète (A, AAAA, MX, TXT, NS, CNAME, SOA)
- Découverte de sous-domaines
- Analyse des enregistrements SPF et DMARC
- Détection CDN et WAF

### 2. Détection Technologies Base de Données
- **MySQL** : ports 3306, détection via erreurs
- **PostgreSQL** : ports 5432, patterns spécifiques
- **MongoDB** : ports 27017, patterns NoSQL
- **Redis** : ports 6379, cache detection
- **Elasticsearch** : ports 9200, recherche full-text
- **MSSQL** : ports 1433, Microsoft SQL Server
- **Oracle** : ports 1521, détection Oracle
- **SQLite** : détection fichiers .db, .sqlite
- **Firebase** : détection Realtime Database / Firestore
- **Supabase** : détection URL Supabase
- **DynamoDB** : patterns AWS

### 3. Analyse de Sécurité
- Headers de sécurité manquants
- Cookies non sécurisés
- Formulaires sans CSRF
- Fuites d'informations sensibles
- Fichiers exposés (.env, config, backup)
- Endpoints API découverts

### 4. Rapports Détaillés
- Rapport HTML interactif avec graphiques
- Rapport JSON structuré
- Rapport TXT détaillé
- Export des résultats bruts

## Installation

```bash
pip install -r requirements_HIDBASE.txt
```

## Utilisation

```bash
# Analyse standard
python3 HIDBASE.py https://example.com

# Analyse approfondie
python3 HIDBASE.py https://example.com --deep

# Avec tous les formats
python3 HIDBASE.py https://example.com --deep --json --txt

# Analyse rapide sans détails
python3 HIDBASE.py https://example.com --no-details
```

## Options

| Option | Description |
|--------|-------------|
| `url` | URL du site cible |
| `-o, --output` | Dossier de sortie (défaut: hidbase_reports) |
| `-t, --timeout` | Timeout des requêtes en secondes (défaut: 10) |
| `--deep` | Analyse approfondie (lente mais complète) |
| `--json` | Exporter en JSON |
| `--txt` | Exporter en TXT |
| `--no-details` | Ne pas demander de détails |

## Exemple de Sortie

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║  HIDBASE - Database Discovery & Analysis Tool                                 ║
║  Développé par HiddenWorld - Informaticien Tchadien                          ║
╚═══════════════════════════════════════════════════════════════════════════════╝

[OPERATION] Résolution DNS
────────────────────────────────────────────────────────────
[██████████████████████████████████████████████████] 100%
────────────────────────────────────────────────────────────
[✓ SUCCESS] DNS résolu: 192.168.1.1

[OPERATION] Détection technologies base de données
────────────────────────────────────────────────────────────
[██████████████████████████████████████████████████] 100%
────────────────────────────────────────────────────────────
[✓ SUCCESS] Technologies détectées: MySQL, Redis
```

## Avertissement

**Cet outil est destiné à des fins éducatives et de tests de sécurité autorisés uniquement.** L'utilisation non autorisée de cet outil contre des systèmes sans permission explicite est illégale.

## Auteur

**HiddenWorld** - Informaticien Tchadien 🇹🇩

---

*HIDBASE - Découvrez ce qui est caché.*
