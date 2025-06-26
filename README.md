# DMS

Ein plattformübergreifendes Dokumentenmanagementsystem (DMS) für Windows, Linux, Mac, iOS und Android.

---

## Aufgabenliste (ToDo)

- [X] **Projektstruktur anlegen**
- [x] **Minimales Hauptfenster mit barrierearmer GUI (Qt/PySide6)**
- [x] **Importfunktion für Dokumente**
- [x] **AES-256 Verschlüsselung für importierte Dokumente**
- [x] **Ablage temporärer Dateien im verschlüsselten Bereich**
- [x] **Exportfunktion für Dokumente**
- [x] **Ordnerüberwachung für automatische Importe**
- [ ] **Dokumentenvorschau (PDF, Bilder, Office)**
- [ ] **Zugriff auf lokale Scanner und Drucker**
- [ ] **Volltextsuche inkl. OCR**
- [ ] **Versionierung von Dokumenten**
- [ ] **Tagging und Metadatenverwaltung**
- [ ] **Backup- und Restore-Funktion**
- [ ] **Benachrichtigungen bei Änderungen**
- [ ] **Mehrsprachigkeit der Oberfläche**
- [ ] **Rechtemanagement**
- [ ] **REST-API Schnittstelle**
- [ ] **Barrierefreiheit/Inklusion prüfen (Screenreader, Tastatur, Kontrast)**
- [ ] **Portable Ausführung vom USB-Stick (PyInstaller o.ä.)**
- [ ] **Sicherheitsfunktionen (Passwort/Biometrie)**
- [ ] **Dokumentation und Benutzerhandbuch**

---

## Hauptfunktionen

- **Portabel:** Das DMS kann direkt von einem USB-Stick aus gestartet werden, ohne Installation auf dem Zielsystem.
- **Sichere Verschlüsselung:** Alle importierten Dokumente werden mit AES-256 verschlüsselt gespeichert. Auch temporäre Dateien werden ausschließlich im verschlüsselten Bereich abgelegt.
- **Import/Export:** Einfache Import- und Exportfunktionen für Dokumente und Ordner.
- **Ordnerüberwachung:** Automatische Überwachung definierter Ordner zur Erkennung und zum Import neuer Dateien.
- **Modernes UI:** Benutzeroberfläche orientiert sich an aktuellen DMS-Systemen und bietet eine intuitive Bedienung.
- **Dokumentenvorschau:** Vorschau für verschiedene Dokumenttypen (z.B. PDF, Bilder, Office-Dateien), die das Dokument visuell anzeigt, nicht nur den Inhalt.
- **Scanner- und Druckerzugriff:** Direkter Zugriff auf lokale Scanner und Drucker zur Digitalisierung und Ausgabe von Dokumenten.
- **Volltextsuche:** Durchsuchbarkeit aller gespeicherten Dokumente (inkl. OCR für gescannte Dokumente).
- **Versionierung:** Automatische Versionierung von Dokumenten bei Änderungen.
- **Tagging und Metadaten:** Möglichkeit, Dokumente mit Tags und Metadaten zu versehen.
- **Backup und Wiederherstellung:** Integrierte Backup- und Restore-Funktion für alle Daten.
- **Benachrichtigungen:** Automatische Benachrichtigungen bei neuen oder geänderten Dokumenten.
- **Mehrsprachigkeit:** Unterstützung mehrerer Sprachen in der Benutzeroberfläche.

## Weitere sinnvolle Funktionen für ein DMS

- **Rechtemanagement:** Benutzer- und Rechteverwaltung für den Zugriff auf Dokumente und Funktionen.
- **API-Schnittstelle:** Möglichkeit zur Integration mit anderen Systemen über eine REST-API.

## Sicherheit

- Alle Daten werden verschlüsselt gespeichert.
- Temporäre Dateien verlassen nie den verschlüsselten Bereich.
- Zugriffsschutz durch Passwort oder biometrische Authentifizierung.

## Plattformen

- Windows
- Linux
- macOS
- iOS
- Android

---

*Diese README beschreibt die geplanten Funktionen und Anforderungen für das DMS-Projekt.*
>>>>>>> f55a107 (Initial DMS Projektstand)
