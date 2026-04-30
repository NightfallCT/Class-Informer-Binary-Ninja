"""
Class Informer for Binary Ninja
================================
Port of the IDA Pro Class Informer plugin by Sirmabus / kweatherman.
Scans MSVC-compiled binaries for C++ RTTI data, identifies vftables,
reconstructs class hierarchies, and annotates the binary.

Original: https://github.com/kweatherman/IDA_ClassInformer_PlugIn
License: MIT
"""

from binaryninja import (
    PluginCommand,
    BackgroundTaskThread,
    log_info,
    log_warn,
    log_error,
    execute_on_main_thread,
)
from binaryninja.interaction import show_message_box, MessageBoxButtonSet, MessageBoxIcon

from .rtti import RTTIScanner
from .vftable import VftableScanner
from .ui import ClassInformerResultsPane


def run_class_informer(bv):
    """Entry point called by Binary Ninja menu / command palette."""
    if bv is None:
        show_message_box(
            "Class Informer",
            "No binary loaded.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    task = ClassInformerTask(bv)
    task.start()

def aboutBox(some):
    show_message_box("Class Informer for Binary Ninja","A Port of the IDA Pro Class Informer plugin by Sirmabus / kweatherman.\nScans MSVC-compiled binaries for C++ RTTI data, identifies vftables,\nreconstructs class hierarchies, and annotates the binary.\n\nMade by NightfallCT\n")
    return


class ClassInformerTask(BackgroundTaskThread):
    """
    Runs the full scan in a background thread so Binary Ninja's UI stays
    responsive.  Mirrors the plugin's scan → annotate → display flow.
    """

    def __init__(self, bv):
        super().__init__("Class Informer: scanning for RTTI / vftables…", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        log_info("[ClassInformer] Starting scan…")

        # ── 1. Detect platform (32 / 64 bit) ──────────────────────────────
        is_64 = bv.arch.address_size == 8
        ptr_size = 8 if is_64 else 4
        log_info(f"[ClassInformer] Architecture: {'64' if is_64 else '32'}-bit, ptr_size={ptr_size}")

        if self.cancelled:
            return

        # ── 2. Scan for RTTI structures ────────────────────────────────────
        rtti_scanner = RTTIScanner(bv, is_64, ptr_size)
        rtti_scanner.scan(progress_cb=self._progress)

        if self.cancelled:
            return

        # ── 3. Scan for vftables (using validated COL addresses) ───────────
        vft_scanner = VftableScanner(bv, rtti_scanner, is_64, ptr_size)
        vft_scanner.scan(progress_cb=self._progress)

        if self.cancelled:
            return

        # ── 4. Annotate binary (names, comments, structs) ─────────────────
        self.progress = "Class Informer: annotating binary…"
        rtti_scanner.annotate()
        vft_scanner.annotate()

        # ── 5. Show results ────────────────────────────────────────────────
        results = vft_scanner.get_results()
        log_info(f"[ClassInformer] Done. Found {len(results)} vftable(s).")
        execute_on_main_thread(lambda: ClassInformerResultsPane.show(bv, results))

    def _progress(self, message: str):
        self.progress = message


# ── Plugin registration ────────────────────────────────────────────────────

PluginCommand.register(
    "Class Informer\\About",
    "Show information about the Class Informer plugin",
    aboutBox,
)

PluginCommand.register(
    "Class Informer\\Run Scan",
    "Scan MSVC binary for RTTI / vftables and reconstruct class hierarchy",
    run_class_informer,
)
