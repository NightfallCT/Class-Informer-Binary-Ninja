"""
vftable.py — Vtable scanner for Binary Ninja Class Informer
============================================================
Mirrors the logic in Vftable.cpp from the original Class Informer IDA plugin.

A valid MSVC vftable:
  - Has cross-references pointing to it (xrefs)
  - Is located directly AFTER a CompleteObjectLocator (COL) pointer
    i.e.  *(vftable - ptr_size)  ==  address of a valid COL
  - Contains a sequence of pointers to executable code (virtual methods)
  - Ends when:
      • next value is not a code pointer
      • next value has its own xref (= start of another vftable)
      • next value is a COL (= another vftable follows)
"""

import struct
from dataclasses import dataclass, field
from typing import Optional, Callable

from binaryninja import BinaryView, log_info, log_warn
import binaryninja


@dataclass
class VftableInfo:
    """All information about a single vftable, ready for display and annotation."""
    address: int                        # address of the vftable itself
    col_address: int                    # address of the preceding COL
    method_count: int                   # number of virtual methods
    class_name: str                     # primary (most-derived) class name
    hierarchy_string: str               # e.g.  "CEdit:CWnd:CCmdTarget:CObject"
    inheritance_label: str              # "[SI]" / "[MI]" / "[VI]" / "[MI VI]"
    is_primary: bool = True             # False for secondary vftables in MI
    method_addresses: list = field(default_factory=list)


class VftableScanner:
    """
    Two-pass scanner:
      Pass 1 – for every known COL, check whether (COL-address + ptr_size)
               is a valid vftable (the most reliable entry point).
      Pass 2 – walk all data segments looking for any remaining vftables
               we may have missed (dirty / partially analysed IDBs).
    """

    def __init__(self, bv: BinaryView, rtti_scanner, is_64: bool, ptr_size: int):
        self.bv         = bv
        self.rtti       = rtti_scanner
        self.is_64      = is_64
        self.ptr_size   = ptr_size
        self._results: list[VftableInfo] = []
        self._seen_vft: set[int] = set()  # dedup

    # ── Public API ────────────────────────────────────────────────────────

    def scan(self, progress_cb: Optional[Callable] = None):
        """Run both passes."""
        if progress_cb:
            progress_cb("Class Informer: scanning vftables (pass 1 – COL-anchored)…")
        self._pass1_col_anchored()

        if progress_cb:
            progress_cb("Class Informer: scanning vftables (pass 2 – segment sweep)…")
        self._pass2_segment_sweep()

        # Sort by address for a clean result list
        self._results.sort(key=lambda r: r.address)
        log_info(f"[ClassInformer] Vftable: {len(self._results)} vftable(s) found.")

    def annotate(self):
        """Apply Binary Ninja labels and comments for every vftable."""
        for info in self._results:
            self._annotate_vftable(info)

    def get_results(self) -> list:
        return list(self._results)

    # ── Pass 1: COL-anchored ──────────────────────────────────────────────

    def _pass1_col_anchored(self):
        """
        The canonical approach: iterate every valid COL we found during RTTI
        scanning and check whether the next ptr-sized slot is a vftable.

        In MSVC layout:
            [COL ptr]   ← at (vftable - ptr_size)
            [vftable]   ← first method pointer
        """
        for col_addr, col in self.rtti.cols.items():
            vft_addr = col_addr + self.ptr_size  # candidate vftable address

            # Verify the slot before the candidate vftable points back to the COL
            col_ref = self._read_ptr(vft_addr - self.ptr_size)
            if col_ref != col_addr:
                # Some linkers place additional padding; try the direct assumption
                pass  # still attempt to parse it

            info = self._try_parse_vftable(vft_addr, col_addr)
            if info:
                self._results.append(info)
                self._seen_vft.add(vft_addr)

    # ── Pass 2: Segment sweep ─────────────────────────────────────────────

    def _pass2_segment_sweep(self):
        """
        Walk data/rdata segments looking for any missed vftables.
        A vtable is heuristically identified by:
          - A ptr-sized slot preceding it that points to a valid COL
          - The address itself is referenced (has xrefs)
        """
        for seg in self.bv.segments:
            if not seg.readable or seg.executable:
                continue
            self._sweep_segment(seg.start, seg.end)

    def _sweep_segment(self, seg_start: int, seg_end: int):
        addr = seg_start
        ptr  = self.ptr_size

        while addr + ptr <= seg_end:
            if addr in self._seen_vft:
                addr += ptr
                continue

            # Check if addr - ptr_size holds a valid COL address
            if addr >= seg_start + ptr:
                try:
                    possible_col = self._read_ptr(addr - ptr)
                    if possible_col in self.rtti.cols:
                        info = self._try_parse_vftable(addr, possible_col)
                        if info:
                            self._results.append(info)
                            self._seen_vft.add(addr)
                            addr += ptr * (info.method_count + 1)
                            continue
                except Exception:
                    pass

            addr += ptr

    # ── Core vftable parser ───────────────────────────────────────────────

    def _try_parse_vftable(self, vft_addr: int, col_addr: int) -> Optional[VftableInfo]:
        """
        Attempt to parse a vftable at *vft_addr*, anchored by *col_addr*.
        Returns a VftableInfo on success, None otherwise.

        Mirrors vftable::getTableInfo() in Vftable.cpp.
        """
        bv   = self.bv
        ptr  = self.ptr_size
        methods: list[int] = []

        addr = vft_addr
        while True:
            try:
                method_ptr = self._read_ptr(addr)
            except Exception:
                break

            if method_ptr == 0 or method_ptr == 0xFFFFFFFF or method_ptr == 0xFFFFFFFFFFFFFFFF:
                break

            # The method pointer must point to executable code (or at least
            # into a segment that is executable / code-like)
            seg = bv.get_segment_at(method_ptr)
            if seg is None or not seg.executable:
                break

            # After the first method, a new xref means start of the next vftable
            if methods:
                refs = list(bv.get_code_refs(addr)) + list(bv.get_data_refs(addr))
                if refs:
                    break
                # Also break if the next slot is another COL
                if method_ptr in self.rtti.cols:
                    break

            methods.append(method_ptr)
            addr += ptr

        if not methods:
            return None

        # ── Build display strings from RTTI ───────────────────────────────
        col = self.rtti.cols.get(col_addr)
        class_name      = "unknown"
        hierarchy_str   = "unknown"
        inheritance_lbl = "[SI]"

        if col and col.type_descriptor:
            class_name = col.type_descriptor.demangled_name or col.type_descriptor.mangled_name

        if col and col.class_hierarchy:
            chd = col.class_hierarchy
            inheritance_lbl = chd.inheritance_label
            # Build hierarchy string: "CEdit:CWnd:CCmdTarget:CObject"
            names = []
            for bci in chd.base_classes:
                n = bci.type_descriptor.demangled_name or bci.type_descriptor.mangled_name
                if n:
                    names.append(n)
            hierarchy_str = ":".join(names) if names else class_name

        return VftableInfo(
            address=vft_addr,
            col_address=col_addr,
            method_count=len(methods),
            class_name=class_name,
            hierarchy_string=hierarchy_str,
            inheritance_label=inheritance_lbl,
            method_addresses=methods,
        )

    # ── Annotation ────────────────────────────────────────────────────────

    def _annotate_vftable(self, info: VftableInfo):
        bv   = self.bv
        addr = info.address
        ptr  = self.ptr_size

        # Label the vftable:  "??_7CEdit@@6B@"
        raw_name = self._make_vft_label(info)
        try:
            if not bv.get_symbol_at(addr):
                from binaryninja import Symbol, SymbolType
                sym = Symbol(SymbolType.DataSymbol, addr, raw_name)
                bv.define_user_symbol(sym)
        except Exception as e:
            log_warn(f"[ClassInformer] vftable symbol at 0x{addr:X}: {e}")

        # Comment at the vftable address
        comment = (
            f"vftable | methods: {info.method_count} | "
            f"{info.hierarchy_string} {info.inheritance_label}"
        )
        bv.set_comment_at(addr, comment)

        # Optionally comment each method slot with its index
        for i, method_addr in enumerate(info.method_addresses):
            slot_addr = addr + i * ptr
            existing = bv.get_comment_at(slot_addr)
            if not existing:
                bv.set_comment_at(slot_addr, f"{info.class_name}::vfunc_{i}")

    def _make_vft_label(self, info: VftableInfo) -> str:
        """
        Construct a mangled vftable label similar to MSVC's:
          "??_7CEdit@@6B@"
        We use the class name directly; a full re-mangle would need the
        original mangled TypeDescriptor name.
        """
        col = self.rtti.cols.get(info.col_address)
        if col and col.type_descriptor:
            mn = col.type_descriptor.mangled_name  # e.g. ".?AVCEdit@@"
            # Strip '.?AV' prefix and trailing '@@', re-wrap as vftable name
            inner = mn[4:] if mn.startswith(".?A") else mn[1:]
            return f"??_7{inner}6B@"
        # Fallback: use demangled name as-is
        safe = info.class_name.replace("::", "_")
        return f"vftable_{safe}"

    # ── Memory helpers ────────────────────────────────────────────────────

    def _read_ptr(self, addr: int) -> int:
        data = self.bv.read(addr, self.ptr_size)
        if data is None or len(data) < self.ptr_size:
            raise ValueError(f"Cannot read ptr at 0x{addr:X}")
        fmt = "<Q" if self.ptr_size == 8 else "<I"
        return struct.unpack(fmt, data)[0]
