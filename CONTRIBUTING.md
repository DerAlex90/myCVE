# Mitentwickeln

Eigene Beiträge müssen mit der [myCVE Attribution License 1.0](LICENSE) vereinbar sein. Bestehende Namens-, Copyright- und Lizenzhinweise einschließlich der [NOTICE](NOTICE) erhalten. Neue eigene Urhebernennungen können ergänzt werden. Beiträge räumen dem Projektinhaber nicht automatisch eine gesonderte Umlizenzierungsbefugnis an fremden Beiträgen ein; hierfür ist gegebenenfalls eine separate Vereinbarung erforderlich.

Python 3.12+ und Node.js 24+ verwenden. Der Agent benötigt Go 1.26+; die Release-Builds verwenden Go 1.27. Die Abhängigkeiten stehen in `uv.lock`, `requirements-server.txt`, `frontend/package-lock.json` und `agent/go.mod` / `agent/go.sum`. Setup und Prüfungen sind in der [README](README.md#qualität-prüfen) beschrieben.

## Fehler und Vorschläge

Für Fehler bitte die passende Issue-Vorlage verwenden: betroffene Version, Plattform, reproduzierbare Schritte und erwartetes Verhalten angeben. Bei Matching-Problemen zusätzlich Ökosystem, synthetischen Paketbezeichner und Versionsgrenzen nennen. Sicherheitslücken nach [SECURITY.md](SECURITY.md) melden.

Für Beiträge das Repository forken und einen eigenen Branch erstellen. Ein Pull Request sollte eine zusammenhängende Änderung enthalten und die tatsächlich ausgeführten Prüfungen nennen. Größere Architekturänderungen zuerst in einem Issue beschreiben.

## Fachliche Anforderungen

Matching-Änderungen benötigen fachliche Grenzfalltests: exakte und abweichende Identität, offene Versionsgrenzen, unbekannte Formate, fehlende Versionen und widersprüchliche Quellen. Ein Parser darf eine unvollständige Antwort nicht als belastbares negatives Ergebnis behandeln. Versionen niemals über einen generischen Stringvergleich sortieren.

Neue Adapter müssen offizielle Endpunkte verwenden, TLS prüfen, Zeitlimits und Größenlimits einhalten, Herkunft und Quelländerungsstände speichern und einen sichtbaren Fehlerzustand liefern. Test-Fixtures enthalten ausschließlich kleine, synthetische Datensätze oder eindeutig zuordenbare öffentliche Beispieldaten.

Änderungen an SQLAlchemy-Modellen benötigen eine neue Alembic-Migration. Bestehende Migrationsdateien nach einer Veröffentlichung nicht ändern. Die öffentliche Bibliothek unter `mycve.core` bleibt von Server- und Netzwerkimporten unabhängig.

Vor einem Pull Request die Python-Prüfungen, den Frontend-Build und betroffene Browser-Workflows ausführen. Titel und Beschreibung sollen das geänderte Verhalten, dessen Grund und die tatsächliche Validierung erklären. In Beispielen und Screenshots keine echten Inventardaten oder Schlüssel verwenden.

## Go-Agent prüfen

```bash
cd agent
go test ./...
go vet ./...
go test -race ./...
go run ./cmd/package --out ../dist/agent
```

Der Race Detector benötigt eine unterstützte Plattform und einen C-Compiler. Änderungen an Paketquellen mit Parser-Fixtures und Fällen für fehlende oder unvollständige Erfassung prüfen. Änderungen am Übertragungsprotokoll müssen mit dem Server zusammenpassen; Gerätebindung, Wiederholung und die Trennung manueller Inventare erhalten.

Der native Windows-Diensttest ist in CI für einen isolierten Windows-Runner eingerichtet. Er benötigt Administratorrechte und wird nur mit `MYCVE_TEST_WINDOWS_SERVICE=1` ausgeführt. Ein erfolgreiches Cross-Compile ersetzt diesen Laufzeittest nicht. Die ausführliche Anleitung steht im [Agentenverzeichnis](agent/README.md).
