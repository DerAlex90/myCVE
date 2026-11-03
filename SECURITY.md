# Sicherheitsmodell

myCVE 0.2 betreibt einen gemeinsamen administrativen Workspace mit einem API-Schlüssel. Wer diesen Schlüssel kennt, kann Inventar, Findings, Quellen und Entscheidungen dieses Workspaces lesen und ändern. Mehrbenutzer-Rollen und Mandantentrennung sind nicht implementiert.

Agenten verwenden separat erzeugte, hochentropische Geräteschlüssel. Der Server speichert nur deren SHA-256-Hash und gibt den Schlüssel ausschließlich bei Registrierung/Rotation aus. Er berechtigt nur zum Schreiben des Inventars des zugeordneten Geräts. Die erste Übermittlung bindet die lokale Geräte-ID; eine Neuinstallation kann die Bindung nach administrativer Schlüsselrotation explizit zurücksetzen. Agenten können weder das Workspace-Inventar lesen noch andere Systeme verwalten oder Scans anfordern.

Der Agent akzeptiert keine Fernbefehle, installiert keine Softwareupdates und sendet keine Quelldateien. Der lokale Zustandsbereich enthält Geräte-ID und unbestätigte Inventardaten und benötigt geschützte Dateirechte. Windows-Installer setzen ACLs für SYSTEM/Administratoren, Linux verwendet einen eigenen unprivilegierten Dienstnutzer. HTTPS und Zertifikatsprüfung sind verpflichtend; explizite HTTP-Ausnahmen sind auf Loopback beschränkt. Weiterleitungen werden nicht verfolgt. Die Standardgrenze beträgt zehn neue Berichte pro Gerät und Minute; identische Wiederholungen bleiben möglich.

Die reguläre API startet ohne konfigurierten Schlüssel nicht. Der ausdrücklich aktivierte Entwicklungsmodus und die fiktive Demo sind für Loopback vorgesehen. Für Netzbetrieb HTTPS und die dokumentierte Compose-Konfiguration verwenden.

Schwachstellen im Projekt bitte über einen privaten Sicherheitsbericht des GitHub-Repositories melden, sofern diese Funktion aktiviert ist. Echte Inventare, Zugangsdaten und ausnutzbare Details gehören nicht in öffentliche Issues. Für öffentlich dokumentierbare Fehler reichen synthetische Reproduktionsbeispiele.

Öffentliche Feeds können unvollständig oder widersprüchlich sein. myCVE protokolliert solche Fälle und trennt den Bearbeitungsstatus von fachlicher Betroffenheit. CSAF-Dokumente werden über HTTPS abgerufen; eine kryptografische OpenPGP-Verifikation ist für 0.2 noch offen.
