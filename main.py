import sys
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton, QFileDialog, QVBoxLayout, QHBoxLayout,
    QWidget, QMessageBox, QListWidget, QSizePolicy, QListWidgetItem, QDialog, QTextEdit, QScrollArea, QLineEdit
)
from PySide6.QtGui import QFont, QPixmap, QImage
from PySide6.QtCore import Qt, QSysInfo
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import uuid
from threading import Thread
import time
import mimetypes
try:
    from PySide6.QtMultimediaWidgets import QCameraViewfinder
    from PySide6.QtMultimedia import QCamera, QImageCapture, QMediaDevices
except ImportError:
    QCameraViewfinder = None

IMPORT_DIR = Path("imported_docs")
IMPORT_DIR.mkdir(exist_ok=True)

TEMP_DIR = IMPORT_DIR / "tmp"
TEMP_DIR.mkdir(exist_ok=True)

# Überwachte Ordner werden in einer Datei gespeichert
WATCHED_PATHS_FILE = Path("watched_folders.txt")
def load_watched_folders():
    if WATCHED_PATHS_FILE.exists():
        return [Path(line.strip()) for line in WATCHED_PATHS_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        # Standardmäßig nur "watch_folder"
        default = Path("watch_folder")
        default.mkdir(exist_ok=True)
        return [default]

def save_watched_folders(folders):
    WATCHED_PATHS_FILE.write_text('\n'.join(str(f) for f in folders), encoding="utf-8")

KEY = os.environ.get("DMS_AES_KEY", None)
if not KEY:
    KEY = b"0123456789abcdef0123456789abcdef"
else:
    KEY = KEY.encode("utf-8")
IV_SIZE = 16

def encrypt_file(src_path, dest_path, key):
    backend = default_backend()
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(src_path, "rb") as f_in, open(dest_path, "wb") as f_out:
        f_out.write(iv)
        while True:
            chunk = f_in.read(1024 * 64)
            if not chunk:
                break
            padded = padder.update(chunk)
            if padded:
                f_out.write(encryptor.update(padded))
        padded = padder.finalize()
        if padded:
            f_out.write(encryptor.update(padded))
        f_out.write(encryptor.finalize())

def decrypt_file(src_path, dest_path, key):
    backend = default_backend()
    with open(src_path, "rb") as f_in:
        iv = f_in.read(IV_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        with open(dest_path, "wb") as f_out:
            while True:
                chunk = f_in.read(1024 * 64)
                if not chunk:
                    break
                decrypted = decryptor.update(chunk)
                if decrypted:
                    f_out.write(unpadder.update(decrypted))
            decrypted = decryptor.finalize()
            if decrypted:
                f_out.write(unpadder.update(decrypted))
            try:
                f_out.write(unpadder.finalize())
            except ValueError:
                pass  # Falls Padding fehlschlägt

def create_encrypted_temp_file(data: bytes, key: bytes, suffix: str = ".tmp.enc") -> Path:
    """
    Legt eine temporäre, verschlüsselte Datei im TEMP_DIR an und gibt den Pfad zurück.
    Die Datei wird mit AES-256 verschlüsselt.
    """
    temp_filename = f"{uuid.uuid4().hex}{suffix}"
    temp_path = TEMP_DIR / temp_filename
    backend = default_backend()
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    with open(temp_path, "wb") as f_out:
        f_out.write(iv)
        padded = padder.update(data) + padder.finalize()
        f_out.write(encryptor.update(padded) + encryptor.finalize())
    return temp_path

def delete_temp_file(temp_path: Path):
    """
    Löscht eine temporäre Datei sicher aus dem TEMP_DIR.
    """
    try:
        temp_path.unlink()
    except Exception:
        pass

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DMS – Dokumentenmanagementsystem")
        self.setMinimumSize(1000, 700)

        # Überwachte Ordner laden
        self.watched_folders = load_watched_folders()

        # Linke Seitenleiste (Navigation)
        nav_layout = QVBoxLayout()
        nav_layout.setSpacing(20)

        btn_import = QPushButton("Importieren")
        btn_import.setFont(QFont("Arial", 14))
        btn_import.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_import.clicked.connect(self.import_document)

        btn_export = QPushButton("Exportieren")
        btn_export.setFont(QFont("Arial", 14))
        btn_export.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_export.clicked.connect(self.export_document)

        btn_preview = QPushButton("Vorschau")
        btn_preview.setFont(QFont("Arial", 14))
        btn_preview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_preview.setEnabled(False)

        btn_settings = QPushButton("Einstellungen")
        btn_settings.setFont(QFont("Arial", 14))
        btn_settings.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_settings.setEnabled(False)

        btn_scan = QPushButton("Scannen")
        btn_scan.setFont(QFont("Arial", 14))
        btn_scan.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_scan.clicked.connect(self.scan_document)
        nav_layout.insertWidget(1, btn_scan)  # Button unter "Importieren" einfügen

        nav_layout.addWidget(btn_import)
        nav_layout.addWidget(btn_export)
        nav_layout.addWidget(btn_preview)
        nav_layout.addWidget(btn_settings)
        nav_layout.addStretch()

        nav_widget = QWidget()
        nav_widget.setLayout(nav_layout)
        nav_widget.setFixedWidth(200)

        # Hauptbereich mit Dokumentenliste und Überwachte Ordner
        main_layout = QVBoxLayout()
        label = QLabel("Importierte Dokumente:")
        label.setFont(QFont("Arial", 16))
        main_layout.addWidget(label)

        self.doc_list = QListWidget()
        self.refresh_doc_list()
        main_layout.addWidget(self.doc_list)

        # Suchfeld oben hinzufügen
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Suche in Dokumenten...")
        self.search_box.textChanged.connect(self.search_documents)
        main_layout.insertWidget(1, self.search_box)  # Suchfeld ganz oben

        # Überwachte Ordner anzeigen
        folder_label = QLabel("Überwachte Ordner:")
        folder_label.setFont(QFont("Arial", 12))
        main_layout.addWidget(folder_label)

        self.folder_list = QListWidget()
        self.refresh_folder_list()
        main_layout.addWidget(self.folder_list)

        btn_add_folder = QPushButton("Ordner hinzufügen")
        btn_add_folder.clicked.connect(self.add_watch_folder)
        main_layout.addWidget(btn_add_folder)

        main_layout.addStretch()
        main_widget = QWidget()
        main_widget.setLayout(main_layout)

        # Gesamtlayout
        layout = QHBoxLayout()
        layout.addWidget(nav_widget)
        layout.addWidget(main_widget)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Ordnerüberwachung starten
        self.watching = True
        self.watcher_thread = Thread(target=self.watch_folders, daemon=True)
        self.watcher_thread.start()

        # Vorschau-Button aktivieren
        self.btn_preview = btn_preview
        self.doc_list.currentItemChanged.connect(lambda: self.enable_preview_button())
        btn_preview.setEnabled(False)
        btn_preview.clicked.connect(self.preview_document)

        self.preview_dialog = None
        self.doc_list.currentItemChanged.connect(self.preview_document)  # Vorschau sofort beim Auswählen

    def refresh_doc_list(self):
        self.doc_list.clear()
        for file in sorted(IMPORT_DIR.glob("*.enc")):
            self.doc_list.addItem(file.name)

    def refresh_folder_list(self):
        self.folder_list.clear()
        for folder in self.watched_folders:
            item = QListWidgetItem(str(folder.resolve()))
            self.folder_list.addItem(item)
        # Kontextmenü für Entfernen
        self.folder_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.folder_list.customContextMenuRequested.connect(self.show_folder_context_menu)

    def show_folder_context_menu(self, pos):
        item = self.folder_list.itemAt(pos)
        if item is None:
            return
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self.folder_list)
        remove_action = menu.addAction("Ordner aus Überwachung entfernen")
        action = menu.exec(self.folder_list.mapToGlobal(pos))
        if action == remove_action:
            idx = self.folder_list.row(item)
            if 0 <= idx < len(self.watched_folders):
                removed = self.watched_folders.pop(idx)
                save_watched_folders(self.watched_folders)
                self.refresh_folder_list()

    def add_watch_folder(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.Directory)
        dialog.setOption(QFileDialog.ShowDirsOnly, True)
        if dialog.exec():
            selected = dialog.selectedFiles()
            if selected:
                folder = Path(selected[0])
                if folder not in self.watched_folders:
                    self.watched_folders.append(folder)
                    save_watched_folders(self.watched_folders)
                    self.refresh_folder_list()

    def import_document(self):
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        if file_dialog.exec():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                src_path = Path(selected_files[0])
                dest_path = IMPORT_DIR / (src_path.name + ".enc")
                encrypt_file(src_path, dest_path, KEY)
                QMessageBox.information(self, "Importiert", f"Datei wurde importiert und verschlüsselt gespeichert:\n{dest_path}")

                # Beispiel: Schreibe eine verschlüsselte temporäre Datei (Demo)
                with open(src_path, "rb") as f:
                    data = f.read()
                temp_file = create_encrypted_temp_file(data, KEY)
                delete_temp_file(temp_file)
                self.refresh_doc_list()

    def export_document(self):
        selected = self.doc_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Kein Dokument ausgewählt", "Bitte wählen Sie ein Dokument aus der Liste aus.")
            return
        src_path = IMPORT_DIR / selected.text()
        # Zielpfad wählen
        save_dialog = QFileDialog(self)
        save_dialog.setAcceptMode(QFileDialog.AcceptSave)
        save_dialog.setDirectory(str(Path.home()))
        orig_name = src_path.stem
        save_dialog.selectFile(orig_name)
        if save_dialog.exec():
            dest_files = save_dialog.selectedFiles()
            if dest_files:
                dest_path = Path(dest_files[0])
                try:
                    decrypt_file(src_path, dest_path, KEY)
                    QMessageBox.information(self, "Exportiert", f"Datei wurde entschlüsselt exportiert:\n{dest_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Fehler", f"Fehler beim Exportieren:\n{e}")

    def enable_preview_button(self):
        item = self.doc_list.currentItem()
        self.btn_preview.setEnabled(item is not None)

    def preview_document(self):
        item = self.doc_list.currentItem()
        if not item:
            if self.preview_dialog:
                self.preview_dialog.close()
            return
        enc_path = IMPORT_DIR / item.text()
        # Endung bestimmen (z.B. .pdf, .docx, .csv)
        orig_name = enc_path.name
        if orig_name.endswith('.enc'):
            orig_name = orig_name[:-4]
        orig_suffix = Path(orig_name).suffix or ".tmp"
        from tempfile import NamedTemporaryFile
        with NamedTemporaryFile(delete=False, suffix=orig_suffix) as tmp:
            tmp_path = Path(tmp.name)
        try:
            decrypt_file(enc_path, tmp_path, KEY)
            ext = tmp_path.suffix.lower()
            mime, _ = mimetypes.guess_type(tmp_path.name)
            # Schließe alte Vorschau
            if self.preview_dialog:
                self.preview_dialog.close()
            dlg = QDialog(self)
            dlg.setWindowTitle(f"Vorschau: {item.text()}")
            dlg.setMinimumSize(800, 600)
            layout = QVBoxLayout(dlg)

            if ext in [".txt", ".py", ".md"]:
                with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                textedit = QTextEdit()
                textedit.setReadOnly(True)
                textedit.setText(text)
                layout.addWidget(textedit)
            elif ext == ".csv":
                from PySide6.QtWidgets import QTableWidget, QTableWidgetItem
                import csv
                with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                    sample = f.read(2048)
                    f.seek(0)
                    try:
                        dialect = csv.Sniffer().sniff(sample)
                    except Exception:
                        dialect = csv.excel  # Fallback
                    reader = csv.reader(f, dialect)
                    for row in reader:
                        if any(text in (cell or "").lower() for cell in row):
                            self.doc_list.addItem(file.name)
                            break
            elif ext in [".jpg", ".jpeg", ".png", ".bmp", ".gif"]:
                pixmap = QPixmap(str(tmp_path))
                label = QLabel()
                if not pixmap.isNull():
                    label.setPixmap(pixmap.scaled(700, 900, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                else:
                    label.setText("Bild konnte nicht geladen werden.")
                scroll = QScrollArea()
                scroll.setWidget(label)
                layout.addWidget(scroll)
            elif ext == ".pdf":
                try:
                    import fitz  # PyMuPDF
                    print(f"DEBUG: Öffne PDF: {tmp_path} (Größe: {tmp_path.stat().st_size} Bytes)")
                    doc = fitz.open(str(tmp_path))
                    print(f"DEBUG: PDF Seiten: {doc.page_count}")
                    if doc.page_count > 0:
                        scroll = QScrollArea()
                        content = QWidget()
                        vbox = QVBoxLayout(content)
                        for page_num in range(doc.page_count):
                            page = doc.load_page(page_num)
                            print(f"DEBUG: Seite {page_num+1} geladen")
                            pix = page.get_pixmap()
                            print(f"DEBUG: PixMap: {pix.width}x{pix.height}, alpha={pix.alpha}")
                            label = QLabel()
                            if pix.alpha:
                                img = QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format_RGBA8888)
                            else:
                                img = QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format_RGB888)
                            if not img.isNull():
                                print("DEBUG: Bild erfolgreich erstellt")
                                label.setPixmap(QPixmap.fromImage(img).scaled(700, 900, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                            else:
                                print("DEBUG: Bild ist null!")
                                label.setText(f"PDF-Seite {page_num+1} konnte nicht gerendert werden.")
                            vbox.addWidget(label)
                        scroll.setWidget(content)
                        layout.addWidget(scroll)
                    else:
                        print("DEBUG: Leeres PDF")
                        layout.addWidget(QLabel("Leeres PDF."))
                    doc.close()
                except Exception as e:
                    print(f"DEBUG: Fehler bei PDF-Vorschau: {e}")
                    layout.addWidget(QLabel(f"PDF-Vorschau nicht möglich: {e}"))
            elif ext in [".docx"]:
                try:
                    from docx2txt import process as docx2txt_process
                    text = docx2txt_process(str(tmp_path))
                    textedit = QTextEdit()
                    textedit.setReadOnly(True)
                    textedit.setText(text)
                    layout.addWidget(textedit)
                except Exception as e:
                    layout.addWidget(QLabel(f"Word-Vorschau nicht möglich: {e}"))
            elif ext in [".xlsx"]:
                try:
                    import openpyxl
                    wb = openpyxl.load_workbook(str(tmp_path), read_only=True)
                    text = ""
                    for ws in wb.worksheets:
                        text += f"Tabelle: {ws.title}\n"
                        for row in ws.iter_rows(values_only=True):
                            text += "\t".join([str(cell) if cell is not None else "" for cell in row]) + "\n"
                        text += "\n"
                    textedit = QTextEdit()
                    textedit.setReadOnly(True)
                    textedit.setText(text)
                    layout.addWidget(textedit)
                except Exception as e:
                    layout.addWidget(QLabel(f"Excel-Vorschau nicht möglich: {e}"))
            elif ext in [".pptx"]:
                try:
                    from pptx import Presentation
                    text = ""
                    prs = Presentation(str(tmp_path))
                    for i, slide in enumerate(prs.slides):
                        text += f"Folie {i+1}:\n"
                        for shape in slide.shapes:
                            if hasattr(shape, "text"):
                                text += shape.text + "\n"
                        text += "\n"
                    textedit = QTextEdit()
                    textedit.setReadOnly(True)
                    textedit.setText(text)
                    layout.addWidget(textedit)
                except Exception as e:
                    layout.addWidget(QLabel(f"PowerPoint-Vorschau nicht möglich: {e}"))
            else:
                layout.addWidget(QLabel("Keine Vorschau für diesen Dateityp verfügbar."))
            dlg.show()
            self.preview_dialog = dlg
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    def watch_folders(self):
        already_seen = {}
        while self.watching:
            for folder in self.watched_folders:
                if folder not in already_seen:
                    try:
                        already_seen[folder] = set(p.name for p in folder.iterdir() if p.is_file())
                    except Exception:
                        already_seen[folder] = set()
            for folder in list(already_seen.keys()):
                if folder not in self.watched_folders:
                    del already_seen[folder]
            for folder in self.watched_folders:
                if not folder.exists():
                    continue
                try:
                    current_files = set(p.name for p in folder.iterdir() if p.is_file())
                except Exception:
                    continue
                new_files = current_files - already_seen.get(folder, set())
                for filename in new_files:
                    src_path = folder / filename
                    dest_path = IMPORT_DIR / (filename + ".enc")
                    try:
                        encrypt_file(src_path, dest_path, KEY)
                        src_path.unlink()  # Nach Import löschen
                        self.refresh_doc_list()
                    except Exception as e:
                        print(f"Fehler beim automatischen Import aus {folder}: {e}")
                already_seen[folder] = current_files
            time.sleep(2)

    def closeEvent(self, event):
        self.watching = False
        super().closeEvent(event)

    def scan_document(self):
        os_type = QSysInfo.productType().lower()
        if os_type in ["android", "ios"]:
            # Kamera-Dialog für Mobile
            dlg = QDialog(self)
            dlg.setWindowTitle("Kamera-Scan")
            dlg.setMinimumSize(400, 500)
            layout = QVBoxLayout(dlg)

            viewfinder = QCameraViewfinder()
            layout.addWidget(viewfinder)

            camera = QCamera(QMediaDevices.defaultVideoInput())
            image_capture = QImageCapture(camera)
            camera.setViewfinder(viewfinder)
            camera.start()

            btn_capture = QPushButton("Foto aufnehmen")
            layout.addWidget(btn_capture)

            def capture_photo():
                image_capture.captureToFile()
                QMessageBox.information(dlg, "Foto", "Foto aufgenommen und gespeichert.")
                camera.stop()
                dlg.accept()
                # TODO: Importiere das Bild wie ein gescanntes Dokument

            btn_capture.clicked.connect(capture_photo)
            dlg.exec()
        else:
            QMessageBox.information(self, "Scanner", "Hier wird ein lokaler Scanner verwendet (Platzhalter).")
            # TODO: Scanner-Integration für Desktop (TWAIN/SANE/WIA)

    def search_documents(self, text):
        import pytesseract
        from PIL import Image
        text = text.lower()
        self.doc_list.clear()
        print("DEBUG: Suche gestartet")
        if not text.strip():
            self.refresh_doc_list()
            return
        for file in sorted(IMPORT_DIR.glob("*.enc")):
            print(f"DEBUG: Datei gefunden: {file.name}")
            if text in file.name.lower():
                self.doc_list.addItem(file.name)
                continue
            orig_name = file.name
            if orig_name.endswith('.enc'):
                orig_name = orig_name[:-4]
            ext = Path(orig_name).suffix.lower()
            from tempfile import NamedTemporaryFile
            with NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                temp_path = Path(tmp.name)
            try:
                decrypt_file(file, temp_path, KEY)
                if ext in [".txt", ".md", ".py"]:
                    with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                    if text in content:
                        self.doc_list.addItem(file.name)
                        continue
                elif ext == ".csv":
                    import csv
                    with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
                        sample = f.read(2048)
                        f.seek(0)
                        try:
                            dialect = csv.Sniffer().sniff(sample)
                        except Exception:
                            dialect = csv.excel  # Fallback
                        reader = csv.reader(f, dialect)
                        for row in reader:
                            if any(text in (cell or "").lower() for cell in row):
                                self.doc_list.addItem(file.name)
                                break
                elif ext == ".pdf":
                    try:
                        import fitz
                        doc = fitz.open(temp_path)
                        pdf_text = ""
                        for page in doc:
                            page_text = page.get_text()
                            print(f"DEBUG: PDF Seite Text: {page_text[:200]}")
                            pdf_text += page_text.lower()
                        doc.close()
                        print(f"DEBUG: Gesamter PDF-Text: {pdf_text[:500]}")
                        print(f"DEBUG: Suche nach '{text}' in PDF-Text: {text in pdf_text}")
                        if text in pdf_text:
                            print(f"DEBUG: Treffer im PDF-Text ({file.name})")
                            self.doc_list.addItem(file.name)
                            continue
                        # OCR für PDF-Seiten (nur wenn kein Text gefunden)
                        doc = fitz.open(temp_path)
                        for page in doc:
                            pix = page.get_pixmap()
                            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                            ocr_text = pytesseract.image_to_string(img, lang="deu+eng").lower()
                            print(f"DEBUG: OCR-Text: {ocr_text[:200]}")
                            print(f"DEBUG: Suche nach '{text}' in OCR-Text: {text in ocr_text}")
                            if text in ocr_text:
                                print(f"DEBUG: Treffer im OCR ({file.name})")
                                self.doc_list.addItem(file.name)
                                break
                        doc.close()
                    except Exception as e:
                        print(f"DEBUG: Fehler bei PDF-Suche: {e}")
                elif ext in [".jpg", ".jpeg", ".png", ".bmp", ".gif"]:
                    try:
                        img = Image.open(temp_path)
                        ocr_text = pytesseract.image_to_string(img, lang="deu+eng").lower()
                        if text in ocr_text:
                            self.doc_list.addItem(file.name)
                    except Exception:
                        pass
            except Exception as e:
                print(f"DEBUG: Fehler bei Datei {file.name}: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())