from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import base64
import tempfile
import uuid
from dataclasses import dataclass
from typing import Callable, Protocol

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtGui import QColor, QFont, QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


@dataclass(frozen=True)
class DriverRecord:
    device: str
    hardware_id: str
    current: str
    latest: str
    status: str
    source: str
    update_available: bool = False
    priority: str = ""
    update_id: str = ""


class AbstractDriverScanner(Protocol):
    def scan(self) -> list[DriverRecord]: ...


class AbstractDriverInstaller(Protocol):
    def install(self, records: list[DriverRecord], report: Callable[[str], None] | None = None) -> str: ...


def detect_platform(system: str | None = None, os_id: str | None = None) -> str:
    system = system or platform.system()
    if system == "Windows":
        return "windows"
    if system == "Linux":
        if os_id is None:
            try:
                os_id = platform.freedesktop_os_release().get("ID", "")
            except (OSError, AttributeError):
                os_id = ""
        return "fedora" if os_id.lower() == "fedora" else "unsupported"
    return "unsupported"


def run_command(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def parse_lspci(output: str) -> list[DriverRecord]:
    devices: list[DriverRecord] = []
    current_device: dict[str, str] | None = None
    for line in output.splitlines():
        header = re.match(r"^([\da-fA-F:.]+)\s+(.+)$", line)
        if header:
            if devices and devices[-1].current == "Rilevamento in corso":
                previous = devices[-1]
                devices[-1] = DriverRecord(
                    previous.device,
                    previous.hardware_id,
                    "Nessun driver associato",
                    "-",
                    "Verifica richiesta",
                    "pci",
                    priority="yellow",
                )
            id_match = re.search(r"\[([\da-fA-F]{4}:[\da-fA-F]{4})\](?!.*\[)", header.group(2))
            if id_match:
                current_device = {
                    "id": id_match.group(1),
                    "name": re.sub(r"\s*\[[^]]+\]\s*", " ", header.group(2)).strip(),
                    "driver": "",
                }
                devices.append(
                    DriverRecord(
                        current_device["name"],
                        current_device["id"],
                        "Rilevamento in corso",
                        "-",
                        "Rilevato",
                        "pci",
                    )
                )
                continue
            current_device = None
        if current_device and "Kernel driver in use:" in line:
            driver = line.partition(":")[2].strip()
            index = len(devices) - 1
            devices[index] = DriverRecord(
                devices[index].device,
                devices[index].hardware_id,
                driver,
                "-",
                "Driver caricato",
                "pci",
                priority="green",
            )
        elif current_device and "Kernel modules:" in line and devices[-1].current == "Rilevamento in corso":
            modules = line.partition(":")[2].strip()
            devices[-1] = DriverRecord(
                devices[-1].device,
                devices[-1].hardware_id,
                f"Modulo disponibile: {modules}" if modules else "Nessun driver caricato",
                "-",
                "Verifica richiesta",
                "pci",
                priority="yellow",
            )
    if devices and devices[-1].current == "Rilevamento in corso":
        previous = devices[-1]
        devices[-1] = DriverRecord(
            previous.device,
            previous.hardware_id,
            "Nessun driver associato",
            "-",
            "Verifica richiesta",
            "pci",
            priority="yellow",
        )
    return devices


def parse_fwupd_updates(payload: str) -> list[DriverRecord]:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return []
    records: list[DriverRecord] = []
    for device in data.get("Devices", []):
        releases = device.get("Releases", [])
        if not releases:
            continue
        release = releases[0]
        urgency = str(release.get("Urgency", "")).lower()
        device_id = str(device.get("DeviceId", device.get("Guid", "fwupd")))
        records.append(
            DriverRecord(
                str(device.get("Name", "Dispositivo firmware")),
                device_id,
                str(device.get("Version", "Sconosciuta")),
                str(release.get("Version", "Disponibile")),
                "Aggiornamento firmware",
                "fwupd",
                True,
                "red" if urgency in {"critical", "high"} else "yellow",
                device_id,
            )
        )
    return records


def parse_windows_devices(payload: str) -> list[DriverRecord]:
    if not payload.strip():
        return []
    try:
        devices = json.loads(payload)
    except json.JSONDecodeError:
        return []
    if isinstance(devices, dict):
        devices = [devices]
    records: list[DriverRecord] = []
    for device in devices:
        status = str(device.get("Status", "Unknown"))
        version = str(device.get("DriverVersion") or "Non installato")
        healthy = status.lower() == "ok" and version != "Non installato"
        records.append(
            DriverRecord(
                str(device.get("Name") or "Dispositivo PnP"),
                str(device.get("InstanceId") or "ID non disponibile"),
                version,
                "Verifica con Windows Update",
                "OK" if healthy else "Driver mancante o in errore",
                "pnp",
                priority="green" if healthy else "red",
            )
        )
    return records


def parse_dnf_driver_updates(
    package_devices: dict[str, list[DriverRecord]],
    current_versions: dict[str, str],
    output: str,
) -> list[DriverRecord]:
    upgrades: dict[str, str] = {}
    for line in output.splitlines():
        package, separator, version = line.strip().partition("|")
        if separator and package in current_versions and version:
            upgrades[package] = version
    records: list[DriverRecord] = []
    for package, version in upgrades.items():
        for device in package_devices.get(package, []):
            records.append(
                DriverRecord(
                    device.device,
                    device.hardware_id,
                    f"{device.current} ({current_versions[package]})",
                    version,
                    "Aggiornamento RPM driver/kernel disponibile",
                    "rpm",
                    True,
                    "yellow",
                    package,
                )
            )
    return records


class FedoraScanner:
    def scan(self) -> list[DriverRecord]:
        records: list[DriverRecord] = []
        if shutil.which("lspci"):
            result = run_command(["lspci", "-Dnnk"])
            records.extend(parse_lspci(result.stdout))
        if shutil.which("lsusb"):
            result = run_command(["lsusb"])
            for line in result.stdout.splitlines():
                match = re.match(r"Bus\s+\d+\s+Device\s+\d+:\s+ID\s+([\da-fA-F]{4}:[\da-fA-F]{4})\s+(.+)", line)
                if match:
                    records.append(
                        DriverRecord(match.group(2), match.group(1), "Gestito dal kernel", "-", "Dispositivo USB", "usb")
                    )
        if shutil.which("fwupdmgr"):
            result = run_command(["fwupdmgr", "get-updates", "--json"], timeout=60)
            if result.returncode == 0:
                records.extend(parse_fwupd_updates(result.stdout))
        records.extend(self._rpm_driver_updates(records))
        if not records:
            records.append(
                DriverRecord(
                    "Nessun dato hardware disponibile",
                    "Installa pciutils, usbutils e fwupd",
                    "-",
                    "-",
                    "Strumenti mancanti o nessun dispositivo trovato",
                    "info",
                )
            )
        return records

    @staticmethod
    def _rpm_driver_updates(records: list[DriverRecord]) -> list[DriverRecord]:
        modinfo = shutil.which("modinfo")
        rpm = shutil.which("rpm")
        dnf = shutil.which("dnf5") or shutil.which("dnf")
        if not modinfo or not rpm or not dnf:
            return []

        modules: dict[str, list[DriverRecord]] = {}
        for record in records:
            if record.source == "pci" and record.status == "Driver caricato":
                modules.setdefault(record.current, []).append(record)

        package_devices: dict[str, list[DriverRecord]] = {}
        current_versions: dict[str, str] = {}
        for module, devices in modules.items():
            if not re.fullmatch(r"[A-Za-z0-9_-]+", module):
                continue
            location = run_command([modinfo, "-F", "filename", module], timeout=10)
            if location.returncode != 0 or not location.stdout.strip():
                continue
            module_path = location.stdout.strip().splitlines()[0]
            if module_path.startswith("("):
                continue
            owner = run_command([rpm, "-qf", "--qf", "%{NAME}|%{EVR}", module_path], timeout=10)
            package, separator, installed_version = owner.stdout.strip().partition("|")
            if owner.returncode != 0 or not separator or not re.fullmatch(r"[A-Za-z0-9.+_-]+", package):
                continue
            package_devices.setdefault(package, []).extend(devices)
            current_versions[package] = installed_version
        if not current_versions:
            return []

        upgrades = run_command(
            [dnf, "repoquery", "--upgrades", "--queryformat=%{name}|%{evr}\\n", *current_versions],
            timeout=180,
        )
        if upgrades.returncode != 0:
            return []
        return parse_dnf_driver_updates(package_devices, current_versions, upgrades.stdout)


class WindowsScanner:
    def scan(self) -> list[DriverRecord]:
        powershell = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
        devices_script = (
            "$ErrorActionPreference='Stop'; $drivers=@{}; "
            "Get-CimInstance Win32_PnPSignedDriver | ForEach-Object {$drivers[$_.DeviceID]=$_.DriverVersion}; "
            "Get-PnpDevice -PresentOnly | ForEach-Object {$id=$_.InstanceId; "
            "[PSCustomObject]@{Name=$_.FriendlyName;InstanceId=$id;Status=$_.Status;DriverVersion=$drivers[$id]}} "
            "| ConvertTo-Json -Depth 3 -Compress"
        )
        result = run_command([powershell, "-NoProfile", "-NonInteractive", "-Command", devices_script], timeout=60)
        records = parse_windows_devices(result.stdout) if result.returncode == 0 else []

        updates_script = (
            "$ErrorActionPreference='Stop'; $s=New-Object -ComObject Microsoft.Update.Session; "
            "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Driver'\"); "
            "$items=@(); foreach($u in $r.Updates){$items += [PSCustomObject]@{Title=$u.Title; "
            "Id=$u.Identity.UpdateID; Severity=$u.MsrcSeverity; Mandatory=$u.IsMandatory}}; "
            "$items | ConvertTo-Json -Depth 2 -Compress"
        )
        updates = run_command([powershell, "-NoProfile", "-NonInteractive", "-Command", updates_script], timeout=120)
        if updates.returncode == 0 and updates.stdout.strip():
            try:
                available = json.loads(updates.stdout)
                if isinstance(available, dict):
                    available = [available]
                records.extend(
                    DriverRecord(
                        str(update.get("Title", "Aggiornamento driver")),
                        "Catalogo Windows Update",
                        "-",
                        "Disponibile",
                        "Aggiornamento urgente" if update.get("Mandatory") or str(update.get("Severity", "")).lower() in {"critical", "high"} else "Aggiornamento disponibile",
                        "windows-update",
                        True,
                        "red" if update.get("Mandatory") or str(update.get("Severity", "")).lower() in {"critical", "high"} else "yellow",
                        str(update.get("Id", "")),
                    )
                    for update in available
                )
            except json.JSONDecodeError:
                pass
        return records or [
            DriverRecord("Nessun dispositivo restituito", "Verifica PowerShell e WMI", "-", "-", "Scansione non disponibile", "info")
        ]


class NativeInstaller:
    def __init__(self, backend: str) -> None:
        self.backend = backend

    def install(self, records: list[DriverRecord], report: Callable[[str], None] | None = None) -> str:
        report = report or (lambda _message: None)
        if self.backend == "fedora":
            device_ids = list(dict.fromkeys(
                record.update_id or record.hardware_id for record in records
                if record.source == "fwupd" and (record.update_id or record.hardware_id) != "fwupd"
            ))
            rpm_packages = list(dict.fromkeys(
                record.update_id for record in records if record.source == "rpm" and record.update_id
            ))
            if not device_ids and not rpm_packages:
                return "Nessun aggiornamento firmware o pacchetto driver selezionabile."
            if not shutil.which("pkexec"):
                return "pkexec non è disponibile: impossibile richiedere l'autorizzazione Polkit."
            output: list[str] = []
            if rpm_packages:
                dnf = shutil.which("dnf5") or shutil.which("dnf")
                if not dnf:
                    raise RuntimeError("DNF non è installato.")
                report("Richiesta Polkit e aggiornamento dei pacchetti driver selezionati...")
                result = run_command(
                    ["pkexec", dnf, "upgrade", "--refresh", "--assumeyes", *rpm_packages],
                    timeout=1800,
                )
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "DNF non ha completato l'aggiornamento.")
                if result.stdout.strip():
                    output.append(result.stdout.strip())
            if device_ids:
                report("Richiesta Polkit e download firmware selezionato...")
                result = run_command(["pkexec", "fwupdmgr", "update", *device_ids], timeout=900)
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "fwupd non ha completato l'aggiornamento.")
                if result.stdout.strip():
                    output.append(result.stdout.strip())
            return "\n".join(output) or "Aggiornamenti selezionati completati."
        if self.backend == "windows":
            update_ids = list(dict.fromkeys(record.update_id for record in records if record.source == "windows-update" and record.update_id))
            if not update_ids:
                return "Seleziona uno o più aggiornamenti driver Windows prima di installare."
            powershell = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
            quoted_ids = ",".join("'" + update_id.replace("'", "''") + "'" for update_id in update_ids)
            status_path = os.path.join(tempfile.gettempdir(), f"driverdesk-{uuid.uuid4().hex}.log")
            script = (
                f"$statusPath='{status_path}'; "
                "function Send-Status($message){Add-Content -Path $statusPath -Value $message -Encoding UTF8}; "
                "trap {Send-Status ('ERROR|'+$_.Exception.Message); exit 1}; "
                "$ErrorActionPreference='Stop'; "
                f"$wanted=@({quoted_ids}); "
                "$session=New-Object -ComObject Microsoft.Update.Session; "
                "$search=$session.CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Driver'\"); "
                "$updates=New-Object -ComObject Microsoft.Update.UpdateColl; "
                "foreach($u in $search.Updates){if($wanted -contains $u.Identity.UpdateID){"
                "if(-not $u.EulaAccepted){$u.AcceptEula()}; [void]$updates.Add($u)}}; "
                "if($updates.Count -eq 0){Send-Status 'RESULT|Gli aggiornamenti selezionati non sono più disponibili'; exit 0}; "
                "Send-Status 'PHASE|Download degli aggiornamenti driver...'; "
                "$downloader=$session.CreateUpdateDownloader(); $downloader.Updates=$updates; "
                "$download=$downloader.Download(); if($download.ResultCode -ge 3){throw 'Download non riuscito'}; "
                "Send-Status 'PHASE|Installazione degli aggiornamenti driver...'; "
                "$installer=$session.CreateUpdateInstaller(); $installer.Updates=$updates; "
                "$result=$installer.Install(); if($result.ResultCode -ge 3){throw 'Installazione non riuscita'}; "
                "Send-Status ('RESULT|Installati: '+$updates.Count+'; riavvio richiesto: '+$result.RebootRequired)"
            )
            encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            escaped_powershell = powershell.replace("'", "''")
            escaped_status_path = status_path.replace("'", "''")
            wrapper = (
                "$ErrorActionPreference='Stop'; "
                f"$statusPath='{escaped_status_path}'; "
                f"$child=Start-Process -FilePath '{escaped_powershell}' -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile -NonInteractive -EncodedCommand {encoded_script}' -PassThru; "
                "$last=''; do { $child.Refresh(); "
                "if(Test-Path $statusPath){$line=Get-Content $statusPath -Tail 1; if($line -and $line -ne $last){Write-Output $line; $last=$line}}; "
                "if(-not $child.HasExited){Start-Sleep -Milliseconds 350} } while(-not $child.HasExited); "
                "$child.Refresh(); exit $child.ExitCode"
            )
            encoded_wrapper = base64.b64encode(wrapper.encode("utf-16le")).decode("ascii")
            report("Richiesta UAC e connessione a Windows Update Agent...")
            try:
                process = subprocess.Popen(
                    [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_wrapper],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                output: list[str] = []
                if process.stdout is not None:
                    for line in process.stdout:
                        line = line.strip()
                        if line.startswith("PHASE|"):
                            report(line.partition("|")[2])
                        elif line.startswith("RESULT|"):
                            output.append(line.partition("|")[2])
                        elif line.startswith("ERROR|"):
                            output.append(line.partition("|")[2])
                        elif line:
                            output.append(line)
                return_code = process.wait()
                if return_code != 0:
                    raise RuntimeError("\n".join(output[-8:]) or f"Windows Update Agent terminato con codice {return_code}.")
                return "\n".join(output) or "Windows Update Agent ha completato la procedura."
            finally:
                try:
                    os.remove(status_path)
                except FileNotFoundError:
                    pass
        return "Sistema operativo non supportato."


class ProviderFactory:
    @staticmethod
    def create(backend: str | None = None) -> tuple[AbstractDriverScanner, AbstractDriverInstaller, str]:
        backend = backend or detect_platform()
        if backend == "fedora":
            return FedoraScanner(), NativeInstaller(backend), "Fedora Linux"
        if backend == "windows":
            return WindowsScanner(), NativeInstaller(backend), "Windows 10/11"
        return FedoraScanner(), NativeInstaller("unsupported"), "Sistema non supportato"


class ScanWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, scanner: AbstractDriverScanner) -> None:
        super().__init__()
        self.scanner = scanner

    def run(self) -> None:
        try:
            self.completed.emit(self.scanner.scan())
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            self.failed.emit(str(error))


class ActionWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, installer: AbstractDriverInstaller, records: list[DriverRecord]) -> None:
        super().__init__()
        self.installer = installer
        self.records = records

    def run(self) -> None:
        try:
            self.completed.emit(self.installer.install(self.records, self.progress.emit))
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            self.failed.emit(str(error))


class DriverDesk(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.scanner, self.installer, self.os_label = ProviderFactory.create()
        self.records: list[DriverRecord] = []
        self._close_pending = False
        self._close_waiting: list[QThread] = []
        self.setWindowTitle("DriverDesk")
        self.setMinimumSize(1000, 680)
        self.resize(1220, 780)
        self.setStyleSheet(STYLESHEET)
        self._build_ui()
        self.start_scan()

    def _build_ui(self) -> None:
        root = QWidget()
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(218)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(22, 25, 18, 22)
        side.setSpacing(12)
        brand = QLabel("DRIVER\nDESK")
        brand.setObjectName("brand")
        side.addWidget(brand)
        side.addSpacing(32)
        side.addWidget(self._nav_label("01", "Panoramica", active=True))
        side.addWidget(self._nav_label("02", "Dispositivi"))
        side.addWidget(self._nav_label("03", "Aggiornamenti"))
        side.addStretch()
        side.addWidget(QLabel("PROTOTIPO\nRilevamento locale,\ninstallazione nativa"))
        outer.addWidget(sidebar)

        content = QWidget()
        content.setObjectName("content")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(34, 27, 34, 24)
        layout.setSpacing(16)

        top = QHBoxLayout()
        eyebrow = QLabel("CENTRO DI CONTROLLO HARDWARE")
        eyebrow.setObjectName("eyebrow")
        top.addWidget(eyebrow)
        top.addStretch()
        self.os_badge = QLabel(f"●  {self.os_label}")
        self.os_badge.setObjectName("osBadge")
        top.addWidget(self.os_badge)
        layout.addLayout(top)

        title_row = QHBoxLayout()
        titles = QVBoxLayout()
        title = QLabel("I tuoi driver,\n sotto controllo.")
        title.setObjectName("title")
        title.setText("I tuoi driver, sotto controllo.")
        subtitle = QLabel("Scansione hardware e aggiornamenti verificati tramite i canali ufficiali del sistema.")
        subtitle.setObjectName("subtitle")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        title_row.addLayout(titles)
        title_row.addStretch()
        self.scan_button = QPushButton("  Scansiona ora")
        self.scan_button.setObjectName("primaryButton")
        self.scan_button.clicked.connect(self.start_scan)
        title_row.addWidget(self.scan_button, alignment=Qt.AlignmentFlag.AlignBottom)
        layout.addLayout(title_row)

        summary = QHBoxLayout()
        summary.setSpacing(12)
        self.device_stat = self._stat_panel("DISPOSITIVI", "--", "Rilevati nel sistema")
        self.update_stat = self._stat_panel("AGGIORNAMENTI", "--", "Disponibili nei canali nativi")
        self.health_stat = self._stat_panel("STATO", "Pronto", "Ultima scansione in attesa")
        summary.addWidget(self.device_stat)
        summary.addWidget(self.update_stat)
        summary.addWidget(self.health_stat)
        layout.addLayout(summary)

        section = QHBoxLayout()
        section_title = QVBoxLayout()
        section_heading = QLabel("Inventario dispositivi")
        section_heading.setObjectName("sectionTitle")
        section_note = QLabel("Driver, firmware e stato rilevati da questo dispositivo")
        section_note.setObjectName("muted")
        section_title.addWidget(section_heading)
        section_title.addWidget(section_note)
        section.addLayout(section_title)
        section.addStretch()
        legend = QHBoxLayout()
        legend.setSpacing(10)
        for color, text in (("#bd3e3a", "Urgente"), ("#a66a08", "Da aggiornare / verificare"), ("#187a58", "OK")):
            marker = QLabel("●")
            marker.setStyleSheet(f"color: {color}; font-size: 12px;")
            label = QLabel(text)
            label.setObjectName("muted")
            legend.addWidget(marker)
            legend.addWidget(label)
        section.addLayout(legend)
        self.update_button = QPushButton("  Installa aggiornamenti")
        self.update_button.setObjectName("secondaryButton")
        self.update_button.clicked.connect(self.start_action)
        section.addWidget(self.update_button, alignment=Qt.AlignmentFlag.AlignBottom)
        layout.addLayout(section)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["DISPOSITIVO", "ID HARDWARE", "VERSIONE ATTUALE", "DISPONIBILE", "ESITO"])
        self.table.setObjectName("deviceTable")
        self.table.setAlternatingRowColors(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, self.table.horizontalHeader().ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, self.table.horizontalHeader().ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, self.table.horizontalHeader().ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, self.table.horizontalHeader().ResizeMode.ResizeToContents)
        layout.addWidget(self.table, 1)

        footer = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setObjectName("progress")
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(170)
        self.progress.hide()
        self.status = QLabel("Pronto per la scansione")
        self.status.setObjectName("muted")
        footer.addWidget(self.progress)
        footer.addWidget(self.status)
        footer.addStretch()
        footer.addWidget(QLabel("Le installazioni richiedono conferma nel sistema operativo"))
        layout.addLayout(footer)
        outer.addWidget(content, 1)
        self.setCentralWidget(root)

    @staticmethod
    def _nav_label(number: str, text: str, active: bool = False) -> QLabel:
        label = QLabel(f"{number}     {text}")
        label.setObjectName("navActive" if active else "navItem")
        return label

    @staticmethod
    def _stat_panel(label: str, value: str, note: str) -> QFrame:
        panel = QFrame()
        panel.setObjectName("statPanel")
        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        panel.setFixedHeight(106)
        box = QVBoxLayout(panel)
        box.setContentsMargins(17, 13, 17, 12)
        box.setSpacing(3)
        caption = QLabel(label)
        caption.setObjectName("statCaption")
        number = QLabel(value)
        number.setObjectName("statValue")
        detail = QLabel(note)
        detail.setObjectName("muted")
        box.addWidget(caption)
        box.addWidget(number)
        box.addWidget(detail)
        panel.value_label = number  # type: ignore[attr-defined]
        panel.note_label = detail  # type: ignore[attr-defined]
        return panel

    def start_scan(self) -> None:
        self.scan_button.setEnabled(False)
        self.status.setText("Scansione in corso...")
        self.progress.setRange(0, 0)
        self.progress.show()
        self.worker = ScanWorker(self.scanner)
        self.worker.completed.connect(self.show_records)
        self.worker.failed.connect(self.show_error)
        self.worker.finished.connect(self.scan_finished)
        self.worker.start()

    def show_records(self, records: list[DriverRecord]) -> None:
        self.records = records
        self.table.setRowCount(len(records))
        colors = {
            "red": ("#a9322d", "#fce8e6"),
            "yellow": ("#8a5a00", "#fff1cc"),
            "green": ("#187a58", "#e2f2e9"),
        }
        labels = {"red": "URGENTE", "yellow": "DA AGGIORNARE / VERIFICARE", "green": "OK"}
        for row, record in enumerate(records):
            priority = record.priority if record.priority in colors else record_priority(record)
            values = [record.device, record.hardware_id, record.current, record.latest, record.status]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 4:
                    foreground, background = colors[priority]
                    item.setText(f"{labels[priority]}  |  {value}")
                    item.setForeground(QColor(foreground))
                    item.setBackground(QColor(background))
                self.table.setItem(row, column, item)
        device_count = len({(record.source, record.hardware_id) for record in records if record.source in {"pci", "usb", "pnp"}})
        self.device_stat.value_label.setText(str(device_count))
        available = len({
            (record.source, record.update_id or record.hardware_id)
            for record in records if record.update_available
        })
        self.update_stat.value_label.setText(str(available))
        priorities = [record.priority if record.priority in colors else record_priority(record) for record in records]
        urgent = priorities.count("red")
        review = priorities.count("yellow")
        self.health_stat.value_label.setText("Urgente" if urgent else "Attenzione" if review else "OK")
        self.health_stat.value_label.setStyleSheet(
            f"color: {colors['red'][0] if urgent else colors['yellow'][0] if review else colors['green'][0]};"
        )
        self.health_stat.note_label.setText(f"{urgent} urgenti · {review} da aggiornare/verificare")
        self.status.setText(f"Scansione completata · {len(records)} elementi")

    def scan_finished(self) -> None:
        self.scan_button.setEnabled(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.progress.hide()

    def show_error(self, message: str) -> None:
        self.status.setText(f"Scansione non completata: {message}")
        self.health_stat.value_label.setText("Errore")

    def start_action(self) -> None:
        selected_rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        selected_updates = [
            self.records[row] for row in selected_rows
            if row < len(self.records) and self.records[row].update_available
        ]
        if not selected_updates:
            selected_updates = [record for record in self.records if record.update_available]
        if not selected_updates:
            QMessageBox.information(self, "Aggiornamenti", "Non ci sono aggiornamenti selezionabili trovati dai canali supportati.")
            return
        unique_updates: dict[tuple[str, str], DriverRecord] = {}
        for record in selected_updates:
            unique_updates.setdefault((record.source, record.update_id or record.hardware_id), record)
        update_list = list(unique_updates.values())
        update_names = "\n".join(f"• {record.device} -> {record.latest}" for record in update_list[:8])
        if len(update_list) > 8:
            update_names += f"\n• e altri {len(update_list) - 8}"
        if not QMessageBox.question(
            self,
            "Conferma aggiornamento",
            f"Scaricare e installare questi aggiornamenti tramite il servizio nativo?\n\n{update_names}\n\nPotrebbe essere richiesto un riavvio.",
        ) == QMessageBox.StandardButton.Yes:
            return
        self.update_button.setEnabled(False)
        self.progress.setRange(0, 0)
        self.progress.show()
        self.status.setText("Avvio del servizio di aggiornamento nativo...")
        self.action_worker = ActionWorker(self.installer, selected_updates)
        self.action_worker.completed.connect(self.action_finished)
        self.action_worker.failed.connect(self.show_error)
        self.action_worker.progress.connect(self.status.setText)
        self.action_worker.finished.connect(lambda: self.update_button.setEnabled(True))
        self.action_worker.finished.connect(self.scan_finished)
        self.action_worker.start()

    def action_finished(self, message: str) -> None:
        self.status.setText(message)
        QMessageBox.information(self, "Aggiornamenti", message)

    def closeEvent(self, event: QCloseEvent) -> None:
        workers = [getattr(self, name, None) for name in ("worker", "action_worker")]
        active = [worker for worker in workers if worker is not None and worker.isRunning()]
        if not active:
            event.accept()
            return

        event.ignore()
        self._close_pending = True
        self.status.setText("Attendi il completamento dell'operazione in corso...")
        for worker in active:
            if worker not in self._close_waiting:
                self._close_waiting.append(worker)
                worker.finished.connect(self._close_when_workers_finish)

    def _close_when_workers_finish(self) -> None:
        if not self._close_pending:
            return
        workers = [getattr(self, name, None) for name in ("worker", "action_worker")]
        if not any(worker is not None and worker.isRunning() for worker in workers):
            self._close_pending = False
            self.close()


def record_priority(record: DriverRecord) -> str:
    if record.update_available:
        return "yellow"
    status = record.status.lower()
    if "errore" in status or "mancante" in status or "non installato" in status:
        return "red"
    if "verifica" in status:
        return "yellow"
    return "green"


STYLESHEET = """
QMainWindow, QWidget#content { background: #f3f6f4; color: #142925; }
QFrame#sidebar { background: #143a34; color: #edf5ee; }
QLabel#brand { color: #f0f7ef; font-size: 24px; font-weight: 900; letter-spacing: 1px; }
QLabel#navActive, QLabel#navItem { padding: 11px 8px; font-size: 13px; }
QLabel#navActive { background: #24534a; border-left: 3px solid #e6a65d; color: #ffffff; font-weight: 700; }
QLabel#navItem { color: #b7ccc3; }
QLabel#eyebrow, QLabel#statCaption { color: #73847e; font-size: 10px; font-weight: 800; letter-spacing: 1px; }
QLabel#osBadge { background: #e1ede6; color: #1e6254; border-radius: 7px; padding: 8px 12px; font-weight: 700; }
QLabel#title { font-size: 30px; font-weight: 800; color: #173b34; }
QLabel#subtitle, QLabel#muted { color: #73817c; font-size: 12px; }
QLabel#sectionTitle { font-size: 18px; font-weight: 800; color: #173b34; }
QFrame#statPanel { background: #ffffff; border: 1px solid #e1e8e3; border-radius: 7px; }
QLabel#statValue { color: #173b34; font-size: 24px; font-weight: 800; }
QPushButton { min-height: 37px; padding: 0 14px; border-radius: 6px; font-weight: 700; }
QPushButton#primaryButton { background: #d77d46; border: 1px solid #d77d46; color: white; }
QPushButton#primaryButton:hover { background: #c96935; }
QPushButton#secondaryButton { background: #ffffff; border: 1px solid #cddbd2; color: #24584c; }
QPushButton#secondaryButton:hover { background: #e8f1eb; }
QPushButton:disabled { color: #9ba9a3; background: #e8ece9; border-color: #e8ece9; }
QTableWidget#deviceTable { background: #ffffff; border: 1px solid #e1e8e3; border-radius: 7px; gridline-color: #edf1ee; selection-background-color: #e5f0e9; selection-color: #173b34; }
QHeaderView::section { background: #f8faf8; color: #73847e; padding: 11px 9px; border: none; border-bottom: 1px solid #e5ebe6; font-size: 10px; font-weight: 800; }
QTableWidget::item { padding: 9px 6px; border-bottom: 1px solid #edf1ee; }
QProgressBar#progress { border: none; border-radius: 3px; background: #dfe8e1; }
QProgressBar#progress::chunk { border-radius: 3px; background: #d77d46; }
"""


def main() -> int:
    if detect_platform() == "unsupported":
        print("DriverDesk supporta Fedora Linux e Windows 10/11.", file=sys.stderr)
        return 2
    app = QApplication(sys.argv)
    app.setApplicationName("DriverDesk")
    app.setFont(QFont("Noto Sans", 10))
    window = DriverDesk()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())