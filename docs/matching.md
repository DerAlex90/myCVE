# Nachvollziehbares Matching

## Identität

Paketnamen werden nur innerhalb desselben Ökosystems verglichen. PyPI folgt der Namensnormalisierung aus PEP 503; NuGet ignoriert Groß-/Kleinschreibung und crates.io behandelt Bindestrich/Unterstrich entsprechend seiner Namensregeln. PURLs werden strukturiert ausgewertet; bei Maven wird die Identität als `group:artifact`, bei npm inklusive Scope erfasst.

Ein Name allein bestätigt keine Produktzuordnung. CVE-CNA-Angaben benötigen einen passenden Hersteller und ein passendes Produkt; angegebene Plattformen müssen ebenfalls geklärt sein. NVD-CPEs berücksichtigen Part, Vendor, Product, Version und weitere Attribute. Wildcard-Inventare können zusätzliche Plattformbedingungen nicht bestätigen.

## Automatische Produktzuordnung

Der Server prüft alle aktiven Installationen automatisch. Bereits vorhandene OSV-/PURL-/CPE-Kennungen werden übernommen. Für klassisches Anwendungsinventar sucht er im [offiziellen NVD-CPE-Katalog](https://nvd.nist.gov/developers/products) und verlangt eine eindeutige Übereinstimmung von Hersteller und Produkt. Produktnamen werden um die gemeldete Version und bekannte Architekturzusätze bereinigt. Ähnliche Namen allein bestätigen keine Zuordnung; widersprüchliche Hersteller, mehrere Produkte und nicht passende Plattformen bleiben ungeklärt.

Die katalogbestätigte Produktidentität wird mit der tatsächlich gemeldeten Version, Plattform und bekannten Architektur kombiniert. Diese zusammengesetzte CPE muss nicht selbst als vollständiger Eintrag im Katalog stehen. Das ursprüngliche Inventar bleibt unverändert; separat gespeichert werden Quelle, Prüfsumme, Katalogbeleg, Entscheidung, Zeitstand und nächster Prüfzeitpunkt. Eine Versions- oder Identitätsänderung verwirft die alte Zuordnung automatisch.

Neue und ausstehende Produkte haben Vorrang. Standardmäßig werden höchstens 50 neue Produktsuchen pro Durchlauf gestartet; weitere folgen automatisch. Katalogseiten werden vollständig bis maximal 50.000 Einträgen geladen, niemals als unvollständiger negativer Beleg verwendet. Ergebnisse werden zwischen Geräten geteilt: bestätigte Produkte sieben Tage, ungeklärte Produkte einen Tag, Abruffehler 15 Minuten. Für fehlende Versionen prüft der Windows-Agent zusätzliche Registry-Werte, MSI-Produktversionen und Hersteller-/Produkt-identische lokale Dateiressourcen. Keine Anwendung wird dafür gestartet.

Bekannte Hersteller-/Markennamen werden anhand begrenzter Regeln vereinheitlicht: [Python Software Foundation](https://www.python.org/psf/), [Mozilla Foundation](https://www.mozilla.org/en-US/foundation/), [The Document Foundation / LibreOffice](https://www.libreoffice.org/about-us/who-are-we/), [Igor Pavlov / 7-Zip](https://www.7-zip.org/), [win.rar / RARLAB](https://www.win-rar.com/), [Adobe Systems](https://www.adobe.com/about-adobe.html), [Git Development Community](https://git-scm.com/) und [OpenSSL](https://www.openssl.org/). Auch diese Namen benötigen anschließend einen passenden offiziellen CPE-Produkteintrag.

Für Debian, Ubuntu und Alpine werden Quellpakete und Distributionsversion verwendet; für AlmaLinux, Rocky Linux und RHEL ihr eigenes RPM-/OSV-Ökosystem. Ein nicht unterstütztes Distributionsinventar wird nicht in die Versionsregeln eines ähnlichen Systems oder eines ungepatchten Upstream-Pakets umgedeutet. Die zugrunde liegenden [OSV-Ökosysteme](https://github.com/google/osv.dev/blob/master/osv/ecosystems/_ecosystems.py) bleiben getrennt.

## Versionen

- PyPI: PEP 440 über `packaging`.
- Klassische CPE-Software: numerische, durch Punkte getrennte Versionen, einschließlich vierteiliger Windows-Versionen; andere Formate bleiben ungeklärt.
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
