# Datenquellen und Herkunft

myCVE verwendet offizielle Endpunkte und dokumentiert am jeweiligen Datensatz die tatsächlich verwendete URL. Die eigene Projektlizenz ersetzt keine Bedingungen von Meldungstexten und Drittanbietern. Ab 0.4.0 gilt die [myCVE Attribution License 1.0](../LICENSE); frühere MIT-Freigaben bleiben unberührt.

| Quelle | Offizieller Einstieg | Verwendung |
| --- | --- | --- |
| CVE Program | [cvelistV5](https://github.com/CVEProject/cvelistV5) | CVE-5-Datensätze, CNA-Produktstatus, Beschreibungen, Änderungen |
| NVD | [CVE API](https://nvd.nist.gov/developers/vulnerabilities) | CVSS, CPE-Kandidaten und Konfigurationen |
| CISA KEV | [Katalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Bekannte Ausnutzung, Quellfristen und Handlungshinweise |
| CISA KEV Spiegel | [cisagov/kev-data](https://github.com/cisagov/kev-data) | Offizieller Fallback, wenn die CISA-Website nicht erreichbar ist |
| BSI CSAF | [CERT-Bund Provider-Metadaten](https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json) | Öffentliche Sicherheitshinweise und exakte Produktstatus |
| OSV | [API-Dokumentation](https://google.github.io/osv.dev/api/) | Paketidentität, Versionsbereiche, Aliase, zurückgezogene Meldungen |

Der OSV-Batch-Endpunkt liefert IDs und Änderungsstände. Für Bewertungen und Versionsinformationen lädt myCVE anschließend die vollständigen Dokumente über `/v1/vulns/{id}`. Alle Seiten einer Batch-Abfrage müssen vollständig vorliegen, bevor ein negatives Ergebnis verwendet wird. Siehe [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/).

Die CERT-Bund-Metadaten führen öffentliche WHITE- und eingeschränkt weiterzugebende GREEN-Feeds. myCVE lädt nur öffentliche WHITE/CLEAR-Feeds und übernimmt nur Dokumente mit explizit öffentlicher TLP-Einstufung. Diese Auswahl wird bei jedem Abruf geprüft. OpenPGP-Schlüssel sind in den Metadaten aufgeführt; eine Signaturprüfung ist für diesen ersten Release noch nicht implementiert. Rohdaten, HTTP-URL und kanonische JSON-Prüfsumme dienen der Nachvollziehbarkeit, sind keine digitale Signatur.

NVD-Bewertungen und CNA-Angaben können sich widersprechen oder ändern. myCVE bewahrt die Originalaussagen und frühere Fassungen auf. KEV ist ein positives Ausnutzungssignal; das Fehlen eines Eintrags beweist keine fehlende Ausnutzung.

Vor einer öffentlichen Weiterverteilung größerer Datenbestände sind die jeweils aktuellen Bedingungen der ursprünglichen Anbieter und der in OSV enthaltenen Datenbanken zu prüfen. Diese Anwendung ist für den eigenen Tracker ausgelegt und stellt nicht automatisch einen öffentlichen Feed bereit.
