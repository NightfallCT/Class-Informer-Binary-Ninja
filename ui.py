"""
ui.py — Native Binary Ninja sidebar widget for Class Informer
==============================================================
Uses SidebarWidget + QTableWidget for a real, native table with:
  - Selectable rows
  - Resizable columns (drag column edges)
  - Sortable columns (click header)
  - Double-click navigates to vftable address
  - Live filter by class name
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
        QPushButton,
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
                # Find our widget type and activate it
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

            # ── Filter bar ────────────────────────────────────────────────
            filter_bar = QHBoxLayout()
            filter_bar.setContentsMargins(6, 4, 6, 4)

            self._scan_btn = QPushButton("Scan")
            self._scan_btn.setToolTip("Run Class Informer scan on this binary")
            self._scan_btn.setFixedHeight(22)
            self._scan_btn.clicked.connect(self._on_scan_clicked)
            filter_bar.addWidget(self._scan_btn)

            self._count_label = QLabel("0 vftable(s)")
            self._count_label.setStyleSheet("font-size: 11px; color: #888;")
            filter_bar.addWidget(self._count_label)
            filter_bar.addStretch()

            self._filter = QLineEdit()
            self._filter.setPlaceholderText("Filter…")
            self._filter.setMaximumWidth(250)
            self._filter.textChanged.connect(self._apply_filter)
            self._filter.setClearButtonEnabled(True)
            filter_bar.addWidget(self._filter)

            layout.addLayout(filter_bar)

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

            # Columns: all resizable by user, Hierarchy stretches
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

            # Double-click → navigate to address
            self._table.cellDoubleClicked.connect(self._on_double_click)

            layout.addWidget(self._table)

            # ── Status line ───────────────────────────────────────────────
            self._status = QLabel("Double-click a row to navigate")
            self._status.setStyleSheet("font-size: 10px; color: #666; padding: 2px 6px;")
            layout.addWidget(self._status)

            self.setLayout(layout)

            # Load any existing results for this bv
            if bv and id(bv) in _results_by_bv:
                self.load_results(_results_by_bv[id(bv)])

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
                meth_item.setData(Qt.DisplayRole, info.method_count)  # numeric sort
                class_item = QTableWidgetItem(info.class_name)
                hier_item  = QTableWidgetItem(info.hierarchy_string)
                type_item  = QTableWidgetItem(info.inheritance_label)

                addr_item.setFont(mono)
                addr_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                meth_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                class_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                hier_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                type_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)

                # Store address for navigation
                for item in [addr_item, meth_item, class_item, hier_item, type_item]:
                    item.setData(Qt.UserRole, info.address)

                # Mute secondary MI entries
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

        def _apply_filter(self, text: str):
            q = text.strip().lower()
            visible = 0
            for row in range(self._table.rowCount()):
                if q:
                    match = False
                    for col in [_C_ADDR, _C_CLASS, _C_HIER]:
                        item = self._table.item(row, col)
                        if item and q in item.text().lower():
                            match = True
                            break
                    self._table.setRowHidden(row, not match)
                    if match:
                        visible += 1
                else:
                    self._table.setRowHidden(row, False)
                    visible += 1

            total = self._table.rowCount()
            if q:
                self._count_label.setText(f"{visible} / {total}")
            else:
                self._count_label.setText(f"{total} vftable(s)")

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
                # Fallback
                self._bv.file.navigate(self._bv.view, addr)
                self._status.setText(f"→ 0x{addr:08X}")
            except Exception as e:
                log_warn(f"[ClassInformer] Navigate: {e}")
                self._status.setText(f"Error: {e}")

        def _on_scan_clicked(self):
            if not self._bv:
                self._status.setText("No binary loaded")
                return
            # Lazy import to avoid circular dependency
            from . import ClassInformerTask
            self._scan_btn.setEnabled(False)
            self._scan_btn.setText("Scanning…")
            self._status.setText("Scan running…")
            task = ClassInformerTask(self._bv)
            task.start()

        def notifyViewChanged(self, frame):
            """Called by Binary Ninja when the active view changes."""
            if frame:
                try:
                    vf = frame
                    ctx = vf.actionContext()
                    new_bv = ctx.binaryView
                    if new_bv and new_bv != self._bv:
                        self._bv = new_bv
                        results = _results_by_bv.get(id(new_bv), [])
                        self.load_results(results)
                except Exception:
                    pass

    # ── Sidebar registration ──────────────────────────────────────────────

    class ClassInformerSidebarWidgetType(SidebarWidgetType):
        def __init__(self):
            # Create a simple icon (small "CI" text on solid background)
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

    # Register the sidebar widget type at plugin load time
    Sidebar.addSidebarWidgetType(ClassInformerSidebarWidgetType())
