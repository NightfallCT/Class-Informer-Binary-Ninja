"""
ui.py — Native Binary Ninja sidebar widget for Class Informer
==============================================================
Uses SidebarWidget + QTableWidget for a real, native table with:
  - Selectable rows
  - Resizable columns (drag column edges)
  - Sortable columns (click header)
  - Double-click navigates to vftable address
  - Live filter by class name
  - Save / Load buttons persist results alongside the .bndb file
"""

from binaryninja import log_info, log_warn, execute_on_main_thread

# Module-level result storage: the scan populates this, the sidebar reads it
_results_by_bv = {}   # id(bv) -> list[VftableInfo]
_widgets = []         # keep references alive


def _store_results(bv, results):
    _results_by_bv[id(bv)] = results


# ── Import binaryninjaui FIRST, then PySide6 (mandatory order) ────────────────
try:
    import binaryninjaui
    from binaryninjaui import (
        SidebarWidget, SidebarWidgetType, Sidebar,
        SidebarWidgetLocation, SidebarContextSensitivity,
        UIContext,
    )
    from PySide6.QtWidgets import (
        QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
        QHeaderView, QLabel, QLineEdit, QAbstractItemView, QWidget,
        QPushButton, QMessageBox,
    )
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QImage, QPainter, QColor, QFont, QBrush
    _HAS_UI = True
except ImportError:
    _HAS_UI = False


class ClassInformerResultsPane:
    """Public API called from __init__.py after scan completes."""

    @staticmethod
    def show(bv, results: list):
        if not results:
            log_info("[ClassInformer] No RTTI / vftables found.")
            bv.show_html_report("Class Informer", "<h3>No RTTI / vftables found.</h3>")
            return

        _store_results(bv, results)

        if _HAS_UI:
            # Refresh any existing Class Informer sidebar widgets
            execute_on_main_thread(lambda: _refresh_all_widgets(bv))
            log_info(f"[ClassInformer] {len(results)} vftable(s) — open 'Class Informer' in the sidebar.")
        else:
            # Headless fallback
            _show_text_report(bv, results)


def _refresh_all_widgets(bv):
    """Push new results to any open ClassInformer sidebar widgets."""
    for w in _widgets:
        try:
            if w._bv is bv or id(w._bv) == id(bv):
                w.load_results(_results_by_bv.get(id(bv), []))
        except Exception:
            pass

    # Also trigger sidebar to show if possible
    try:
        ctx = UIContext.activeContext()
        if ctx:
            sb = ctx.sidebar()
            if sb:
                for wt in Sidebar.types():
                    if wt.name() == "Class Informer":
                        sb.activate(wt)
                        break
    except Exception as e:
        log_warn(f"[ClassInformer] Could not auto-open sidebar: {e}")


def _show_text_report(bv, results):
    lines = [f"Class Informer — {len(results)} vftable(s)\n\n"]
    for r in results:
        lines.append(f"  0x{r.address:08X}  {r.method_count:>4}  {r.class_name}  {r.hierarchy_string}  {r.inheritance_label}\n")
    bv.show_plain_text_report("Class Informer", "".join(lines))


# ── Sidebar widget (only defined when UI is available) ─────────────────────────

if _HAS_UI:

    _C_ADDR  = 0
    _C_METH  = 1
    _C_CLASS = 2
    _C_HIER  = 3
    _C_TYPE  = 4
    _COLUMNS = ["Address", "Methods", "Class Name", "Hierarchy", "Type"]

    class ClassInformerSidebarWidget(SidebarWidget):

        def __init__(self, name, frame, bv):
            SidebarWidget.__init__(self, name)
            self._bv = bv
            self._all_results = []
            _widgets.append(self)

            layout = QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            # ── Toolbar ───────────────────────────────────────────────────
            toolbar = QHBoxLayout()
            toolbar.setContentsMargins(6, 4, 6, 4)
            toolbar.setSpacing(4)

            # Scan button
            self._scan_btn = QPushButton("Scan")
            self._scan_btn.setToolTip("Run Class Informer scan on this binary")
            self._scan_btn.setFixedHeight(22)
            self._scan_btn.clicked.connect(self._on_scan_clicked)
            toolbar.addWidget(self._scan_btn)

            # Save button
            self._save_btn = QPushButton("Save")
            self._save_btn.setToolTip("Save current results to a .class_informer.json file next to the database")
            self._save_btn.setFixedHeight(22)
            self._save_btn.setEnabled(False)   # enabled once results exist
            self._save_btn.clicked.connect(self._on_save_clicked)
            toolbar.addWidget(self._save_btn)

            # Load button
            self._load_btn = QPushButton("Load")
            self._load_btn.setToolTip("Load previously saved results from the .class_informer.json file")
            self._load_btn.setFixedHeight(22)
            self._load_btn.clicked.connect(self._on_load_clicked)
            toolbar.addWidget(self._load_btn)

            # Clear button
            self._clear_btn = QPushButton("Clear")
            self._clear_btn.setToolTip("Clear all results from the table")
            self._clear_btn.setFixedHeight(22)
            self._clear_btn.setEnabled(False)   # enabled once results exist
            self._clear_btn.clicked.connect(self._on_clear_clicked)
            toolbar.addWidget(self._clear_btn)

            # Count label + filter (pushed to the right)
            self._count_label = QLabel("0 vftable(s)")
            self._count_label.setStyleSheet("font-size: 11px; color: #888;")
            toolbar.addWidget(self._count_label)
            toolbar.addStretch()

            self._filter = QLineEdit()
            self._filter.setPlaceholderText("Filter…")
            self._filter.setMaximumWidth(220)
            self._filter.textChanged.connect(self._apply_filter)
            self._filter.setClearButtonEnabled(True)
            toolbar.addWidget(self._filter)

            layout.addLayout(toolbar)

            # ── Table ─────────────────────────────────────────────────────
            self._table = QTableWidget(0, len(_COLUMNS))
            self._table.setHorizontalHeaderLabels(_COLUMNS)
            self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self._table.setSelectionMode(QAbstractItemView.SingleSelection)
            self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self._table.verticalHeader().setVisible(False)
            self._table.verticalHeader().setDefaultSectionSize(20)
            self._table.setWordWrap(False)
            self._table.setAlternatingRowColors(True)
            self._table.setSortingEnabled(True)
            self._table.setShowGrid(False)

            hdr = self._table.horizontalHeader()
            hdr.setStretchLastSection(False)
            hdr.setSectionResizeMode(_C_ADDR,  QHeaderView.Interactive)
            hdr.setSectionResizeMode(_C_METH,  QHeaderView.Interactive)
            hdr.setSectionResizeMode(_C_CLASS, QHeaderView.Interactive)
            hdr.setSectionResizeMode(_C_HIER,  QHeaderView.Stretch)
            hdr.setSectionResizeMode(_C_TYPE,  QHeaderView.Interactive)
            self._table.setColumnWidth(_C_ADDR,  110)
            self._table.setColumnWidth(_C_METH,  60)
            self._table.setColumnWidth(_C_CLASS, 180)
            self._table.setColumnWidth(_C_TYPE,  60)

            self._table.cellDoubleClicked.connect(self._on_double_click)

            layout.addWidget(self._table)

            # ── Status line ───────────────────────────────────────────────
            self._status = QLabel("Double-click a row to navigate")
            self._status.setStyleSheet("font-size: 10px; color: #666; padding: 2px 6px;")
            layout.addWidget(self._status)

            self.setLayout(layout)

            # Load any existing in-memory results for this bv, or try the
            # saved file automatically when the sidebar is first opened.
            if bv and id(bv) in _results_by_bv:
                self.load_results(_results_by_bv[id(bv)])
            elif bv:
                self._try_autoload()

        # ── Result loading ─────────────────────────────────────────────────

        def load_results(self, results: list):
            """Populate the table with scan results."""
            self._all_results = results
            self._table.setSortingEnabled(False)
            self._table.setRowCount(0)

            mono = QFont("Consolas", 10)
            mono.setStyleHint(QFont.Monospace)

            for row, info in enumerate(results):
                self._table.insertRow(row)

                addr_item  = QTableWidgetItem(f"0x{info.address:08X}")
                meth_item  = QTableWidgetItem()
                meth_item.setData(Qt.DisplayRole, info.method_count)
                class_item = QTableWidgetItem(info.class_name)
                hier_item  = QTableWidgetItem(info.hierarchy_string)
                type_item  = QTableWidgetItem(info.inheritance_label)

                addr_item.setFont(mono)
                addr_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                meth_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                class_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                hier_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                type_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)

                for item in [addr_item, meth_item, class_item, hier_item, type_item]:
                    item.setData(Qt.UserRole, info.address)

                if not info.is_primary:
                    gray = QBrush(QColor(100, 100, 100))
                    for item in [addr_item, meth_item, class_item, hier_item, type_item]:
                        item.setForeground(gray)

                self._table.setItem(row, _C_ADDR,  addr_item)
                self._table.setItem(row, _C_METH,  meth_item)
                self._table.setItem(row, _C_CLASS, class_item)
                self._table.setItem(row, _C_HIER,  hier_item)
                self._table.setItem(row, _C_TYPE,  type_item)

            self._table.setSortingEnabled(True)
            self._count_label.setText(f"{len(results)} vftable(s)")
            self._status.setText("Double-click a row to navigate")
            self._scan_btn.setEnabled(True)
            self._scan_btn.setText("Scan")

            # Enable Save only when there is something to save
            has_results = len(results) > 0
            self._save_btn.setEnabled(has_results)
            self._clear_btn.setEnabled(has_results)

        # ── Filter ─────────────────────────────────────────────────────────

        def _apply_filter(self, text: str):
            q = text.strip().lower()
            visible = 0
            for row in range(self._table.rowCount()):
                if q:
                    match = any(
                        (item := self._table.item(row, col)) and q in item.text().lower()
                        for col in [_C_ADDR, _C_CLASS, _C_HIER]
                    )
                    self._table.setRowHidden(row, not match)
                    if match:
                        visible += 1
                else:
                    self._table.setRowHidden(row, False)
                    visible += 1

            total = self._table.rowCount()
            self._count_label.setText(f"{visible} / {total}" if q else f"{total} vftable(s)")

        # ── Navigation ─────────────────────────────────────────────────────

        def _on_double_click(self, row, col):
            item = self._table.item(row, _C_ADDR)
            if not item:
                return
            addr = item.data(Qt.UserRole)
            if addr is None:
                return
            try:
                ctx = UIContext.activeContext()
                if ctx:
                    vf = ctx.getCurrentViewFrame()
                    if vf:
                        vf.navigate(f"Linear:{self._bv.view_type}", addr)
                        self._status.setText(f"→ 0x{addr:08X}")
                        return
                self._bv.file.navigate(self._bv.view, addr)
                self._status.setText(f"→ 0x{addr:08X}")
            except Exception as e:
                log_warn(f"[ClassInformer] Navigate: {e}")
                self._status.setText(f"Error: {e}")

        # ── Scan ───────────────────────────────────────────────────────────

        def _on_scan_clicked(self):
            if not self._bv:
                self._status.setText("No binary loaded")
                return
            from . import ClassInformerTask
            self._scan_btn.setEnabled(False)
            self._scan_btn.setText("Scanning…")
            self._save_btn.setEnabled(False)
            self._status.setText("Scan running…")
            task = ClassInformerTask(self._bv)
            task.start()

        # ── Save ───────────────────────────────────────────────────────────

        def _on_save_clicked(self):
            if not self._bv:
                self._status.setText("No binary loaded")
                return
            if not self._all_results:
                self._status.setText("Nothing to save — run a scan first")
                return

            try:
                from .persistence import save_results, results_path_for
                path = save_results(self._bv, self._all_results)
                self._status.setText(f"Saved → {path}")
            except Exception as e:
                log_warn(f"[ClassInformer] Save failed: {e}")
                self._status.setText(f"Save failed: {e}")
                QMessageBox.warning(
                    self, "Class Informer — Save Failed",
                    f"Could not save results:\n\n{e}",
                )

        # ── Load ───────────────────────────────────────────────────────────

        def _on_load_clicked(self):
            """Manually load saved results (shows an error dialog on failure)."""
            if not self._bv:
                self._status.setText("No binary loaded")
                return

            try:
                from .persistence import load_results, results_path_for
                results = load_results(self._bv)
                _store_results(self._bv, results)
                self.load_results(results)
                path = results_path_for(self._bv)
                self._status.setText(f"Loaded {len(results)} vftable(s) ← {path}")
            except FileNotFoundError as e:
                self._status.setText("No saved results found for this binary")
                QMessageBox.information(
                    self, "Class Informer — Load",
                    str(e),
                )
            except Exception as e:
                log_warn(f"[ClassInformer] Load failed: {e}")
                self._status.setText(f"Load failed: {e}")
                QMessageBox.warning(
                    self, "Class Informer — Load Failed",
                    f"Could not load results:\n\n{e}",
                )

        # ── Clear ──────────────────────────────────────────────────────────

        def _on_clear_clicked(self):
            """Clear all results from the table and reset in-memory state."""
            self._all_results = []
            if self._bv:
                _results_by_bv.pop(id(self._bv), None)
            self._filter.clear()
            self._table.setSortingEnabled(False)
            self._table.setRowCount(0)
            self._table.setSortingEnabled(True)
            self._count_label.setText("0 vftable(s)")
            self._status.setText("Results cleared")
            self._save_btn.setEnabled(False)
            self._clear_btn.setEnabled(False)

        # ── Auto-load on sidebar open ──────────────────────────────────────

        def _try_autoload(self):
            """
            Silently attempt to load saved results when the sidebar widget is
            first created for a binary.  No dialog shown on failure — the user
            can always click Load manually.
            """
            if not self._bv:
                return
            try:
                from .persistence import load_results, results_path_for
                results = load_results(self._bv)
                _store_results(self._bv, results)
                self.load_results(results)
                path = results_path_for(self._bv)
                self._status.setText(f"Auto-loaded {len(results)} vftable(s) ← {path}")
                log_info(f"[ClassInformer] Auto-loaded {len(results)} result(s) from {path}")
            except FileNotFoundError:
                # Nothing saved yet — perfectly normal, stay silent
                pass
            except Exception as e:
                log_warn(f"[ClassInformer] Auto-load skipped: {e}")

        # ── View change ────────────────────────────────────────────────────

        def notifyViewChanged(self, frame):
            """Called by Binary Ninja when the active view changes."""
            if frame:
                try:
                    ctx = frame.actionContext()
                    new_bv = ctx.binaryView
                    if new_bv and new_bv != self._bv:
                        self._bv = new_bv
                        results = _results_by_bv.get(id(new_bv), [])
                        if results:
                            self.load_results(results)
                        else:
                            # Try loading from disk for the new binary
                            self._try_autoload()
                except Exception:
                    pass

    # ── Sidebar registration ──────────────────────────────────────────────────

    class ClassInformerSidebarWidgetType(SidebarWidgetType):
        def __init__(self):
            icon = QImage(56, 56, QImage.Format_ARGB32)
            icon.fill(QColor(0, 0, 0, 0))
            p = QPainter(icon)
            p.setRenderHint(QPainter.Antialiasing)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(78, 201, 176))  # teal
            p.drawRoundedRect(4, 4, 48, 48, 8, 8)
            p.setPen(QColor(30, 30, 30))
            f = QFont("Arial", 18, QFont.Bold)
            p.setFont(f)
            p.drawText(icon.rect(), Qt.AlignCenter, "CI")
            p.end()

            SidebarWidgetType.__init__(self, icon, "Class Informer")

        def createWidget(self, frame, data):
            return ClassInformerSidebarWidget("Class Informer", frame, data)

        def contextSensitivity(self):
            return SidebarContextSensitivity.SelfManagedSidebarContext

        def defaultLocation(self):
            return SidebarWidgetLocation.RightBottom

    Sidebar.addSidebarWidgetType(ClassInformerSidebarWidgetType())