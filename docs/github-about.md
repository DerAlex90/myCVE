# GitHub-Projektangaben

Die Projektdateien und die GitHub-Seitenleiste sind getrennte Einstellungen. GitHub übernimmt die [vorbereiteten Werte](../.github/repository-metadata.json) nicht automatisch aus dem Repository. Die hier angebundene Integration darf Dateien schreiben, erhält beim Ändern der Repository-Einstellungen aber `403 Resource not accessible by integration`.

## Im GitHub-Browser setzen

Als Repository-Inhaber auf [myCVE](https://github.com/DerAlex90/myCVE) rechts neben **About** auf das Zahnrad klicken und diese Werte speichern. Die Einstellungen gelten für das gesamte Repository, unabhängig vom angezeigten Branch.

**Description**

```text
Automatischer CVE-Tracker mit Inventar-Agenten für Linux und Windows. Python-Bibliothek, nachvollziehbarer Abgleich und Self-Hosting. Von Alexander Speka (DerAlex90).
```

**Website / Dokumentation**

```text
https://github.com/DerAlex90/myCVE#readme
```

**Topics** – einzeln hinzufügen:

```text
cve, vulnerability-management, software-inventory, inventory-agent, sbom, csaf, osv, nvd, self-hosted, python, golang, linux, windows, source-available, attribution
```

## Mit eigener GitHub-CLI-Sitzung

Die Vorschau ändert nichts:

```bash
python scripts/configure_github_about.py --dry-run
```

Mit einem für dieses Repository zur Administration berechtigten Zugang können die Werte gesetzt werden:

```bash
python scripts/configure_github_about.py
```

Ein als Inhaber angemeldeter Nutzer allein genügt nicht, wenn dessen verwendetes App-Token die erforderlichen Rechte nicht besitzt. Keine Tokens in Dateien oder Issues veröffentlichen.
