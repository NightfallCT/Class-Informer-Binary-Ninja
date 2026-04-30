"""
rtti.py — MSVC RTTI structure scanner for Binary Ninja
=======================================================
Mirrors the logic in RTTI.cpp from the original Class Informer IDA plugin.

MSVC RTTI layout (simplified):
  vftable[-1]  →  CompleteObjectLocator (COL)
  COL          →  TypeDescriptor  (class name, mangled)
  COL          →  ClassHierarchyDescriptor (CHD)
  CHD          →  BaseClassArray  →  BaseClassDescriptor[] (BCD)

32-bit: all pointers are absolute virtual addresses.
64-bit: COL uses *relative* 32-bit offsets from an image base stored in
        COL.objectBase.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional
import ctypes

import binaryninja
from binaryninja import BinaryView, log_info, log_warn


# ── RTTI struct sizes (in bytes) ──────────────────────────────────────────

# type_info (TypeDescriptor) layout:
#   ptr  vfptr
#   ptr  _M_data  (NULL at static init time)
#   char _M_d_name[]  (mangled name, starts with '.')

# CompleteObjectLocator (COL) 32-bit:
#   u32  signature   (0)
#   u32  offset
#   u32  cdOffset
#   u32  typeDescriptor   (abs ptr)
#   u32  classDescriptor  (abs ptr)

# CompleteObjectLocator (COL) 64-bit:
#   u32  signature   (1)
#   u32  offset
#   u32  cdOffset
#   u32  typeDescriptor   (rel offset)
#   u32  classDescriptor  (rel offset)
#   u32  objectBase       (rel offset to image base)

# ClassHierarchyDescriptor (CHD):
#   u32  signature
#   u32  attributes   bit0=MI, bit1=VI
#   u32  numBaseClasses
#   ptr/u32  baseClassArray   (abs or rel)

# BaseClassDescriptor (BCD):
#   ptr/u32  typeDescriptor
#   u32      numContainedBases
#   i32      pmd.mdisp
#   i32      pmd.pdisp
#   i32      pmd.vdisp
#   u32      attributes
#   ptr/u32  classDescriptor  (only when BCD_HASPCHD set)

CHD_MULTINH = 0x01
CHD_VIRTINH = 0x02
BCD_HASPCHD = 0x40


@dataclass
class TypeDescriptor:
    address: int
    mangled_name: str          # e.g.  ".?AVCEdit@@"
    demangled_name: str = ""   # e.g.  "CEdit"


@dataclass
class BaseClassInfo:
    type_descriptor: "TypeDescriptor"
    num_contained_bases: int
    mdisp: int
    pdisp: int
    vdisp: int
    attributes: int


@dataclass
class ClassHierarchyDescriptor:
    address: int
    attributes: int
    base_classes: list = field(default_factory=list)  # list[BaseClassInfo]

    @property
    def is_multiple_inheritance(self) -> bool:
        return bool(self.attributes & CHD_MULTINH)

    @property
    def is_virtual_inheritance(self) -> bool:
        return bool(self.attributes & CHD_VIRTINH)

    @property
    def inheritance_label(self) -> str:
        mi = self.is_multiple_inheritance
        vi = self.is_virtual_inheritance
        if mi and vi:
            return "[MI VI]"
        if mi:
            return "[MI]"
        if vi:
            return "[VI]"
        return "[SI]"


@dataclass
class CompleteObjectLocator:
    address: int
    type_descriptor: Optional[TypeDescriptor] = None
    class_hierarchy: Optional[ClassHierarchyDescriptor] = None


class RTTIScanner:
    """
    Walks all readable data segments looking for valid MSVC RTTI structures.

    Scanning strategy (same as original Class Informer):
      1. Find TypeDescriptors by looking for the type_info vftable pointer
         followed by a NULL _M_data field and a mangled name starting with '.'.
      2. Find COLs that reference known TypeDescriptors.
      3. From each COL walk to CHD → BCD[] to build the class hierarchy.
    """

    def __init__(self, bv: BinaryView, is_64: bool, ptr_size: int):
        self.bv = bv
        self.is_64 = is_64
        self.ptr_size = ptr_size

        # Result sets (address → parsed object), mirrors IDA's eaSet / maps
        self.type_descriptors: dict[int, TypeDescriptor] = {}
        self.cols: dict[int, CompleteObjectLocator] = {}
        self.chds: dict[int, ClassHierarchyDescriptor] = {}

        # Cache: address → name string (avoids repeated reads)
        self._string_cache: dict[int, str] = {}

        # Precomputed: address of type_info vftable (the "?? _7type_info" symbol)
        self._type_info_vftable: Optional[int] = self._find_type_info_vftable()

    # ── Public API ────────────────────────────────────────────────────────

    def scan(self, progress_cb=None):
        """Full scan: TypeDescriptors → COLs → CHDs."""
        if progress_cb:
            progress_cb("Class Informer: scanning TypeDescriptors…")
        self._scan_type_descriptors()

        if progress_cb:
            progress_cb("Class Informer: scanning CompleteObjectLocators…")
        self._scan_cols()

        if progress_cb:
            progress_cb("Class Informer: resolving class hierarchies…")
        self._resolve_hierarchies()

        log_info(
            f"[ClassInformer] RTTI: {len(self.type_descriptors)} TypeDescriptor(s), "
            f"{len(self.cols)} COL(s), {len(self.chds)} CHD(s)"
        )

    def annotate(self):
        """Apply names / comments to the binary view for all found structures."""
        for addr, td in self.type_descriptors.items():
            self._annotate_type_descriptor(td)

        for addr, col in self.cols.items():
            self._annotate_col(col)

    # ── TypeDescriptor scanning ───────────────────────────────────────────

    def _find_type_info_vftable(self) -> Optional[int]:
        """
        Look up the address of the type_info vftable.
        In MSVC binaries it is exported as "??_7type_info@@6B@".
        """
        sym = self.bv.get_symbol_by_raw_name("??_7type_info@@6B@")
        if sym:
            log_info(f"[ClassInformer] type_info vftable found at 0x{sym.address:X}")
            return sym.address

        # Fallback: search for the mangled name in all symbols
        for sym in self.bv.get_symbols():
            if "type_info" in sym.raw_name and "6B" in sym.raw_name:
                log_info(f"[ClassInformer] type_info vftable (fallback) at 0x{sym.address:X}")
                return sym.address

        log_warn("[ClassInformer] type_info vftable not found; TypeDescriptor validation will be limited.")
        return None

    def _scan_type_descriptors(self):
        """
        Scan all data/rdata sections for potential TypeDescriptors.

        A valid TypeDescriptor looks like:
          [ptr to type_info vftable]  [NULL ptr]  ['.?A' string…]
        """
        for seg in self.bv.segments:
            if not seg.readable:
                continue
            # Only look in non-executable segments (data/rdata)
            if seg.executable:
                continue
            self._scan_segment_for_td(seg.start, seg.end)

    def _scan_segment_for_td(self, seg_start: int, seg_end: int):
        ptr = self.ptr_size
        step = ptr  # align scan to pointer size

        addr = seg_start
        while addr + ptr * 2 + 4 <= seg_end:
            try:
                vfptr = self._read_ptr(addr)
                m_data = self._read_ptr(addr + ptr)
            except Exception:
                addr += step
                continue

            # _M_data must be NULL at static init time
            if m_data != 0:
                addr += step
                continue

            # Optionally verify vfptr points to the known type_info vftable
            if self._type_info_vftable is not None:
                if vfptr != self._type_info_vftable:
                    addr += step
                    continue
            else:
                # Without the vftable address, just check it points somewhere valid
                if not self._is_valid_addr(vfptr):
                    addr += step
                    continue

            # Read the mangled class name at _M_d_name
            name_addr = addr + ptr * 2
            name = self._read_cstring(name_addr)
            if name and self._is_valid_type_name(name):
                demangled = self._demangle_type_name(name)
                td = TypeDescriptor(
                    address=addr,
                    mangled_name=name,
                    demangled_name=demangled,
                )
                self.type_descriptors[addr] = td

            addr += step

    # ── COL scanning ──────────────────────────────────────────────────────

    def _scan_cols(self):
        """
        Search for CompleteObjectLocators.
        Strategy: for each known TypeDescriptor, search backwards in .rdata
        for a COL that references it.  Also do a forward scan per segment.
        """
        for seg in self.bv.segments:
            if not seg.readable or seg.executable:
                continue
            self._scan_segment_for_col(seg.start, seg.end)

    def _scan_segment_for_col(self, seg_start: int, seg_end: int):
        addr = seg_start
        step = 4  # COL starts with a u32 signature, scan at 4-byte alignment

        while addr + self._col_size() <= seg_end:
            if self._try_parse_col(addr):
                # Skip past the structure to avoid re-parsing
                addr += self._col_size()
            else:
                addr += step

    def _col_size(self) -> int:
        return 24 if self.is_64 else 20

    def _try_parse_col(self, addr: int) -> bool:
        """
        Attempt to parse and validate a COL at *addr*.
        Returns True and stores the result if valid.
        """
        try:
            sig = self._read_u32(addr)
        except Exception:
            return False

        if not self.is_64:
            # 32-bit: signature must be 0
            if sig != 0:
                return False
            return self._try_parse_col_32(addr)
        else:
            # 64-bit: signature must be 1
            if sig != 1:
                return False
            return self._try_parse_col_64(addr)

    def _try_parse_col_32(self, addr: int) -> bool:
        try:
            # offset(4) cdOffset(4) typeDescriptor(4) classDescriptor(4)
            td_addr  = self._read_u32(addr + 12)
            chd_addr = self._read_u32(addr + 16)
        except Exception:
            return False

        if td_addr not in self.type_descriptors:
            return False
        if not self._is_valid_addr(chd_addr):
            return False

        col = CompleteObjectLocator(
            address=addr,
            type_descriptor=self.type_descriptors[td_addr],
        )
        self.cols[addr] = col
        return True

    def _try_parse_col_64(self, addr: int) -> bool:
        try:
            # sig(4) offset(4) cdOffset(4) tdOffset(4) chdOffset(4) objBase(4)
            td_off   = self._read_i32(addr + 12)
            chd_off  = self._read_i32(addr + 16)
            obj_base = self._read_i32(addr + 20)
        except Exception:
            return False

        if obj_base == 0:
            return False

        col_base = addr - obj_base
        td_addr  = col_base + td_off
        chd_addr = col_base + chd_off

        if td_addr not in self.type_descriptors:
            return False
        if not self._is_valid_addr(chd_addr):
            return False

        col = CompleteObjectLocator(
            address=addr,
            type_descriptor=self.type_descriptors[td_addr],
        )
        # Store chd_addr for later resolution
        col._chd_addr = chd_addr  # type: ignore[attr-defined]
        col._col_base = col_base  # type: ignore[attr-defined]
        self.cols[addr] = col
        return True

    # ── Hierarchy resolution ──────────────────────────────────────────────

    def _resolve_hierarchies(self):
        """Parse CHD + BCD[] for every found COL."""
        for col in self.cols.values():
            if not self.is_64:
                chd_addr = self._read_u32(col.address + 16)
                col_base = 0
            else:
                chd_addr = getattr(col, "_chd_addr", None)
                col_base = getattr(col, "_col_base", 0)
                if chd_addr is None:
                    continue

            chd = self._parse_chd(chd_addr, col_base)
            if chd:
                col.class_hierarchy = chd

    def _parse_chd(self, chd_addr: int, col_base: int) -> Optional[ClassHierarchyDescriptor]:
        if chd_addr in self.chds:
            return self.chds[chd_addr]

        try:
            # sig(4) attributes(4) numBaseClasses(4) baseClassArray(ptr/u32)
            attributes      = self._read_u32(chd_addr + 4)
            num_base        = self._read_u32(chd_addr + 8)
            if not self.is_64:
                bca_addr = self._read_u32(chd_addr + 12)
            else:
                bca_off  = self._read_i32(chd_addr + 12)
                bca_addr = col_base + bca_off
        except Exception:
            return None

        if num_base > 256:  # sanity cap
            return None

        chd = ClassHierarchyDescriptor(address=chd_addr, attributes=attributes)

        # Parse BaseClassArray → BCD[]
        for i in range(num_base):
            try:
                if not self.is_64:
                    bcd_addr = self._read_u32(bca_addr + i * 4)
                else:
                    bcd_off  = self._read_i32(bca_addr + i * 4)
                    bcd_addr = col_base + bcd_off

                bci = self._parse_bcd(bcd_addr, col_base)
                if bci:
                    chd.base_classes.append(bci)
            except Exception:
                break

        self.chds[chd_addr] = chd
        return chd

    def _parse_bcd(self, bcd_addr: int, col_base: int) -> Optional[BaseClassInfo]:
        try:
            if not self.is_64:
                td_addr = self._read_u32(bcd_addr)
            else:
                td_off  = self._read_i32(bcd_addr)
                td_addr = col_base + td_off

            num_contained = self._read_u32(bcd_addr + 4)
            mdisp         = self._read_i32(bcd_addr + 8)
            pdisp         = self._read_i32(bcd_addr + 12)
            vdisp         = self._read_i32(bcd_addr + 16)
            attributes    = self._read_u32(bcd_addr + 20)
        except Exception:
            return None

        td = self.type_descriptors.get(td_addr)
        if td is None:
            return None

        return BaseClassInfo(
            type_descriptor=td,
            num_contained_bases=num_contained,
            mdisp=mdisp,
            pdisp=pdisp,
            vdisp=vdisp,
            attributes=attributes,
        )

    # ── Annotation ────────────────────────────────────────────────────────

    def _define_symbol(self, addr: int, name: str):
        """Safely define a user data symbol at addr."""
        try:
            if self.bv.get_symbol_at(addr):
                return
            from binaryninja import Symbol, SymbolType
            sym = Symbol(SymbolType.DataSymbol, addr, name)
            self.bv.define_user_symbol(sym)
        except Exception as e:
            log_warn(f"[ClassInformer] Symbol '{name}' at 0x{addr:X}: {e}")

    def _annotate_type_descriptor(self, td: TypeDescriptor):
        addr = td.address
        label = f"??_R0?{td.mangled_name[1:]}8"
        self._define_symbol(addr, label)
        self.bv.set_comment_at(addr, f"TypeDescriptor: {td.demangled_name}")

    def _annotate_col(self, col: CompleteObjectLocator):
        addr = col.address
        if col.type_descriptor:
            label = f"??_R4{col.type_descriptor.mangled_name[2:]}6B@"
            self._define_symbol(addr, label)
            self.bv.set_comment_at(addr, f"COL: {col.type_descriptor.demangled_name}")

    # ── Low-level memory helpers ──────────────────────────────────────────

    def _read_ptr(self, addr: int) -> int:
        data = self.bv.read(addr, self.ptr_size)
        if data is None or len(data) < self.ptr_size:
            raise ValueError(f"Cannot read {self.ptr_size} bytes at 0x{addr:X}")
        fmt = "<Q" if self.ptr_size == 8 else "<I"
        return struct.unpack(fmt, data)[0]

    def _read_u32(self, addr: int) -> int:
        data = self.bv.read(addr, 4)
        if data is None or len(data) < 4:
            raise ValueError(f"Cannot read u32 at 0x{addr:X}")
        return struct.unpack("<I", data)[0]

    def _read_i32(self, addr: int) -> int:
        data = self.bv.read(addr, 4)
        if data is None or len(data) < 4:
            raise ValueError(f"Cannot read i32 at 0x{addr:X}")
        return struct.unpack("<i", data)[0]

    def _read_cstring(self, addr: int, max_len: int = 256) -> Optional[str]:
        if addr in self._string_cache:
            return self._string_cache[addr]
        data = self.bv.read(addr, max_len)
        if not data:
            return None
        end = data.find(b"\x00")
        if end < 0:
            return None
        try:
            s = data[:end].decode("ascii", errors="replace")
            self._string_cache[addr] = s
            return s
        except Exception:
            return None

    def _is_valid_addr(self, addr: int) -> bool:
        if addr == 0 or addr == 0xFFFFFFFF or addr == 0xFFFFFFFFFFFFFFFF:
            return False
        return self.bv.get_segment_at(addr) is not None

    def _is_valid_type_name(self, name: str) -> bool:
        """
        MSVC type names start with '.?A' (class) or '.?AU' (struct).
        More precisely the pattern is '.?A' followed by type code + name + '@@'.
        """
        if not name.startswith(".?A"):
            return False
        if len(name) < 6:
            return False
        return True

    def _demangle_type_name(self, mangled: str) -> str:
        """
        Rough demangling of MSVC TypeDescriptor names.
        '.?AVCEdit@@'  →  'CEdit'
        The real undname() is in the MSVC runtime; we do a best-effort here.
        TODO: use binja's built-in demangler or ctypes undname on Windows.
        """
        # Strip leading '.?Ax' prefix and trailing '@@'
        name = mangled
        if name.startswith(".?A"):
            name = name[4:]   # skip '.?AV' or '.?AU' etc.
        if name.endswith("@@"):
            name = name[:-2]
        # Handle nested names: 'CEdit@MFC@@' → 'MFC::CEdit'
        parts = [p for p in name.split("@") if p]
        parts.reverse()
        return "::".join(parts) if parts else mangled
