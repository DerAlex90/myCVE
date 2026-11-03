# Softwareliste: Befunde aus 0.4.0 und Umsetzung für 0.5.0

Die vom Betreiber gemeldeten **2.777 betroffenen Paketzeilen**, **1.145 Kombinationen aus Schwachstelle, Quellpaket und Version** und **1.632 zusätzlichen Binärpaketzeilen** beziehen sich auf dessen Proxmox-Host. Dessen Inventar liegt dieser Arbeitsumgebung nicht vor. Diese Zahlen werden als gemeldeter Befund geführt; ein synthetischer Regressionstest reproduziert dieselben Größen und prüft, dass kein Paket beim Gruppieren verloren geht.

| Priorität | Punkt | Umsetzung |
| --- | --- | --- |
| Hoch | Kernel-Kontext | Gemeldeter laufender Kernel und exakt zugeordnete installierte Images werden von Header-/Entwicklungspaketen getrennt. `linux-libc-dev` belegt die Betroffenheit des Pakets; es belegt keine Betroffenheit des laufenden Kernels. Ein Wechsel des laufenden Kernels löst auch ohne Paketänderung eine Neubewertung aus. |
| Hoch | Risiken und Pakettreffer | Die Übersicht zählt nach Schwachstelle, Asset, Ökosystem, Quellpaket und Quellversion. Alle Binärpakete bleiben aufklappbar erhalten; eine Paketansicht und getrennte Pakettrefferzähler bleiben verfügbar. |
| Hoch | Runtime / Development / ungeklärt | Kontext, Filter, Typzähler und begründete Priorisierung. Ein Risiko kann mehrere Typen betreffen; Typzähler sind deshalb nicht addierbar. Nicht laufende Kernel und Kernel-Header werden gesondert priorisiert; andere Entwicklungskomponenten bleiben bei Ausnutzungssignalen dringlich. |
| Hoch | Veraltete Oberfläche | Aktualisierung sichtbarer Seiten auch ohne initial laufenden Scan und beim erneuten Aktivieren eines Tabs. Während eines Scans werden Findings nur in ihrer Ansicht geladen; Übersicht und Systemliste haben eigene Abrufabstände. Agenten-Downloads werden pro Seitenaufruf geladen. |
| Hoch | Windows-Upgrade | Private Vorbereitung und Prüfung vor dem Stopp, Sicherung alter Dateien, Austausch ohne Entfernen der bestehenden Dienstdefinition, explizite SYSTEM-/Administratorenrechte sowie Wiederherstellung bei Fehlern. Benutzerdefinierte Dienstkonten werden vor Änderungen zur manuellen Prüfung abgewiesen. |
| Mittel | Patchstatus | `available`, `unavailable`, `unknown`. Eine leere Fixliste bleibt ungeklärt. Eine fehlende Behebung wird nur aus einer ausdrücklichen passenden Quellenangabe abgeleitet; CSAF erfordert exakten Produktbezug. |
| Mittel | Teilfehler / Wiederholungen | Fortgesetzte oder automatisch wiederholte Teilabgleiche verwenden erfolgreich gespeicherte Quellenresultate innerhalb von standardmäßig sechs Stunden. Fehlgeschlagene Abrufe werden erneut ausgeführt. Auswertungen werden erneut auf das aktuelle Inventar angewendet. Neue vollständige Abgleiche verwenden einen neuen Cache-Bereich. |
| Mittel | Fortschritt / Steuerung | Aktuelle Phase, Anzahl bearbeiteter Einheiten, letzte Aktivität, Abruf-/Wiederverwendungszähler sowie kooperativer Abbruch und Fortsetzung als neuer nachvollziehbarer Job. |
| Mittel | CSV-Filter | API und CSV verwenden denselben Filterpfad. Die Oberfläche bietet aktuelle Ansicht, gefilterte Risiken, gefilterte Paketdetails oder ausdrücklich alle Paketdetails. Ein Filter ohne Treffer exportiert nur die Kopfzeile. |
| Mittel | Betriebsüberwachung | Geschützter Betriebsstatus und Readiness prüfen Datenbank, Redis/Queue, Worker-/Scheduler-Lebenszeichen sowie erfolgreiche und fehlgeschlagene Abgleiche. Die HTTP-Lebendprüfung bleibt davon getrennt. |

## Vereinheitlichte Abläufe

- API, CLI und beide Scheduler-Auslöser verwenden dieselbe serialisierte Scan-Erzeugung. Ein Datenbank-Schreib-/Zeilenlock schützt auch gleichzeitige Startanforderungen. Der PostgreSQL-Ausführungslock bleibt zusätzlich erhalten.
- JSON-Anfragen und Downloads teilen Authentifizierung und Fehlerbehandlung. Ein abgelaufener Schlüssel führt auch beim Download zur Anmeldung zurück.
- Fehler bei automatischen Abrufen verschwinden nach einer erfolgreichen Wiederverbindung. Fehler einer Benutzeraktion werden getrennt geführt.
- Die Systemliste lädt Zähler mit Sammelabfragen statt zweier zusätzlicher Abfragen pro System. Die Risiken zählen weiterhin getrennt von ihren Paketzeilen.

## Grenzen und Betrieb

Ein Pakettyp ist eine Einordnung des Inventars und kein Beweis dafür, dass ein Prozess läuft oder aus dem Netz erreichbar ist. Ein Kernel-Image gilt nur bei exakt passender Releasekennung als laufend. Ohne passende Metadaten bleibt der Kernel-Kontext ungeklärt. Distributionsfremde und Proxmox-spezifische Backports dürfen nicht allein aus einer Debian-/SemVer-Ähnlichkeit als betroffen oder behoben eingestuft werden.

Abbruch ist kooperativ: Ein laufender externer Abruf muss seinen Kontrollpunkt oder sein Zeitlimit erreichen. Fortsetzen nutzt gespeicherte erfolgreiche Resultate, beginnt die fachliche Auswertung aber erneut gegen das aktuelle Inventar. Der Wiederverwendungshorizont wird über `MYCVE_SCAN_CACHE_HOURS` (1–24, Standard 6) begrenzt. Zwischenzeitliche andere Abgleiche machen ältere Retry-Ergebnisse ungültig, damit aktuelle Quellenstände erhalten bleiben. Ein inzwischen erfolgreicher letzter Scan wird nicht automatisch durch die Fortsetzung eines älteren Teilfehlers ersetzt. Nach einem vollständig erfolgreichen Abgleich wird dessen temporärer Cache gelöscht; verwaiste Einträge werden bei neuen Jobs nach 24 Stunden entfernt. Quellenbelege und fachliche Historie werden dabei erhalten.

Vor dem Serverupdate ein Backup erstellen. Die neue Migration erhält vorhandene Findings, Notizen und Scanprotokolle und plant vorhandene Agenten zur erneuten Prüfung ein. Den Server vor den neuen Agenten aktualisieren. Die bereits veröffentlichte Version 0.4.0 und deren Download-Dateien werden nicht überschrieben.

## Nachgelagerte Erweiterungen

Diese Erweiterungen sind als weitere Arbeit eingeplant: Benutzerrollen und ein umfassendes administratives Änderungsprotokoll, konfigurierbare Benachrichtigungen für neue wichtige Risiken und ausgefallene Agenten sowie ein geregelter Aufbewahrungs-/Archivierungsprozess mit Wiederherstellungstests für die fachliche Historie. Bestehende Finding-Ereignisse und Quellenrevisionen bleiben weiterhin nachvollziehbar.
