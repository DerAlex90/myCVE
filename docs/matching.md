# Nachvollziehbares Matching

## Identität

Paketnamen werden nur innerhalb desselben Ökosystems verglichen. PyPI folgt der Namensnormalisierung aus PEP 503; NuGet ignoriert Groß-/Kleinschreibung und crates.io behandelt Bindestrich/Unterstrich entsprechend seiner Namensregeln. PURLs werden strukturiert ausgewertet; bei Maven wird die Identität als `group:artifact`, bei npm inklusive Scope erfasst.

Ein Name allein bestätigt keine Produktzuordnung. CVE-CNA-Angaben benötigen einen passenden Hersteller und ein passendes Produkt; angegebene Plattformen müssen ebenfalls geklärt sein. NVD-CPEs berücksichtigen Part, Vendor, Product, Version und weitere Attribute. Wildcard-Inventare können zusätzliche Plattformbedingungen nicht bestätigen.

## Versionen

- PyPI: PEP 440 über `packaging`.
- npm und crates.io: SemVer.
- Go, Maven, NuGet, RubyGems, Packagist, Debian und RPM: die jeweiligen Vergleicher aus `univers`.
- OSV: explizite Versionen sowie `introduced`, `fixed`, `last_affected` und `limit`. Mehrere betroffene Intervalle und erneute Einführungen werden unterstützt.
- CVE-CNA: explizite Versionen und unterstützte `versionType`-Bereiche einschließlich Statusänderungen.
- BSI-CSAF: exakte identifizierbare Produktversionen über PURL/CPE und veröffentlichte Produktstatus.

Ein erfolgreiches, vollständiges OSV-API-Ergebnis für ein exaktes Paket mit Version ist zusätzlicher Beleg. Dadurch können Online-Abfragen auch Ökosysteme abdecken, deren lokale Versionsregeln nicht implementiert sind. Ohne installierte Version bestätigt eine Paketabfrage keine Betroffenheit.

Git-Commit-Bereiche, unbekannte Versionsformate, fehlende Versionen oder unvollständige NVD-AND/NOT-Umgebungsbedingungen bleiben ungeklärt. Es gibt keinen lexikografischen Versionsvergleich als Fallback. Fehlende Meldungen allein sind kein Beleg dafür, dass ein ganzes System frei von Schwachstellen ist.

## Quellenkonflikte

Betroffen und nicht betroffen für dieselbe Installation führt zu `unknown` und einer sichtbaren Konfliktbegründung. Alle einzelnen Aussagen bleiben in den Belegen erhalten. Die Beschreibung bevorzugt OSV, anschließend CNA und NVD; für CVSS wird die aktuelle NVD-Bewertung bevorzugt, ansonsten die aktuelle OSV-Bewertung. Historische, höhere Werte werden nicht dauerhaft als aktueller Wert fortgeschrieben.

Zurückgezogene Meldungen und zurückgewiesene CVEs bleiben als Quellenrevision nachvollziehbar. Wird ein früher erledigtes oder nicht betroffenes Finding durch eine neue installierte Version wieder relevant, wird die Bearbeitung erneut geöffnet.

Fix-Versionen sind veröffentlichte Grenzwerte der zum Paket passenden Meldungen. Sie sind keine pauschale Upgrade-Empfehlung über alle Release-Zweige. Betreiber müssen den passenden Zweig und mögliche Distributions-Backports prüfen.

## Priorität

Der Punktwert ist die Summe aus:

| Signal | Punkte |
| --- | ---: |
| Im KEV-Katalog enthalten | 45 |
| CVSS | gerundet `3 × CVSS` |
| Aus dem Internet erreichbar | 15 |
| Hohe Systemkritikalität | 10 |

Maximal 100 Punkte. Keine CVSS-Bewertung wird als fehlend angezeigt und nicht als technische Schwere null behauptet.

- Nicht betroffen: keine Handlungspriorität.
- Ungeklärt: P1 mit KEV, sonst P2 zur Klärung; niemals P0.
- Bestätigt betroffen + KEV: P0 bei Internet-Erreichbarkeit oder hoher Kritikalität, sonst P1.
- Ohne KEV: P1 ab 40 Punkten, P2 ab 20 Punkten, sonst P3.

Dies ist eine konfigurationsunabhängig dokumentierte Heuristik des ersten Releases. Sie schätzt keine Ausnutzungswahrscheinlichkeit. KEV-Fristen werden als Quellenangabe angezeigt und nicht als allgemein gültige eigene Frist ausgegeben.
