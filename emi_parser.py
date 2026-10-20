"""Parser for the binary format understood by the original ``emi_ext.exe``.

The original tool (Free Pascal, v1.1.2) scans an arbitrary binary for two
20-byte signatures:

* ``AND_ROMINFO_v`` block (version 2) which stores the platform name.
* ``MTK_BIN`` block which stores a device count followed by 188-byte legacy
  records, 160-byte V35 records, or 84-byte V49/V52/V54 records.

This module reproduces that behaviour, including the original tool's global
state across input files (the platform/count/records are *not* reset when a
new file is parsed).

Modern MediaTek preloaders add a ``MTK_BLOADER_INFO_v35`` header before the
``MTK_BIN`` block and use 160-byte (V35) records.  The newer V49/V52/V54
header family uses 84-byte records instead.  Those layouts are parsed too;
the older 188-byte layout is kept unchanged for ``v10`` files and for files
that do not carry a layout header.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import List, Sequence


# ---------------------------------------------------------------------------
# Constants extracted from the original executable and from MTK's structures.
# ---------------------------------------------------------------------------

#: "AND_ROMINFO_v" + 3 NUL padding + little-endian uint32 version == 2.
SIG_ROMINFO = b"AND_ROMINFO_v\x00\x00\x00" + struct.pack("<I", 2)

#: The stable part of the ROMINFO signature.  The four bytes that follow are
#: two little-endian uint16 values (major, minor); major must be 2.
ROMINFO_PREFIX = b"AND_ROMINFO_v\x00\x00\x00"
ROMINFO_VERSION_MAJOR = 2

#: "V116" + 8 binary bytes + "MTK_BIN\0" (exactly 20 bytes).
SIG_MTK_BIN = bytes.fromhex("563131362288443390007000") + b"MTK_BIN\x00"

#: Header that selects the record layout in modern preloaders.
MTK_BLOADER_INFO_PREFIX = b"MTK_BLOADER_INFO_v"

#: Platform name is always read as exactly 6 bytes after the ROMINFO signature.
PLATFORM_SIZE = 6

#: Size of one legacy (V10/V12-style) memory-device record.
RECORD_SIZE = 0xBC

#: Size of one modern V35 memory-device record.
RECORD_SIZE_V35 = 0xA0

#: Size of one V49/V52/V54 memory-device record.  MTK's EMIInfoV49 declares a
#: 56-byte emi_cfg followed by ``emi_len[21]``; the preloader advances by the
#: 84-byte emi_len array, so that is the on-disk stride used here.
RECORD_SIZE_V49 = 0x54

#: Number of EMI register dwords at record offset 0x28 (legacy layout).
REGISTER_COUNT = 17

#: Number of EMI register dwords at record offset 0x28 (V35 layout).
REGISTER_COUNT_V35 = 10

#: Number of MODE_REG dwords at record offset 0xA4 (legacy layout only).
MODE_REG_COUNT = 6

#: Size of the two identifier buffers.
ID_BUFFER_SIZE = 16
FW_ID_BUFFER_SIZE = 8

#: Layout names used by :class:`EmiRecord`.
LAYOUT_LEGACY = "legacy"
LAYOUT_V35 = "v35"
LAYOUT_V49 = "v49"

#: V35 is used by these MTK_BLOADER_INFO major versions.  The v35/v36/v38/v39
#: eMMC EMI structures share the same offset for the fields we read.
V35_LAYOUT_VERSIONS = frozenset({35, 36, 38, 39})

#: V49, V52 and V54 share MTK's EMIInfoV49 structure and 84-byte on-disk
#: records.  MTKPreloaderParser groups these versions together.
V49_LAYOUT_VERSIONS = frozenset({49, 52, 54})


class EmiFormatError(ValueError):
    """Raised when an input file looks like EMI data but is truncated."""


def _is_ascii_alnum(byte: int) -> bool:
    """Match the original filter: only 0-9, A-Z and a-z are kept."""
    return (
        0x30 <= byte <= 0x39
        or 0x41 <= byte <= 0x5A
        or 0x61 <= byte <= 0x7A
    )


@dataclass(frozen=True)
class EmiRecord:
    """A parsed memory-device record.

    ``raw`` is kept intact so callers can inspect fields that are not part of
    the spreadsheet output.  ``layout`` is ``"legacy"`` for the original
    188-byte records, ``"v35"`` for the 160-byte records, or ``"v49"`` for the
    84-byte V49/V52/V54 records.
    """

    raw: bytes
    type_code: int          # +0x04, signed 32-bit
    id_length: int          # +0x08, signed 32-bit
    fw_length: int          # +0x0C, signed 32-bit
    vendor_code: int        # +0x10, byte
    id_field: bytes         # +0x10..+0x1F (16 bytes)
    fw_field: bytes         # +0x20..+0x27 (8 bytes)
    density_low: int        # legacy +0x6C / V35 rank_size[0] low dword
    density_high: int       # legacy +0x70 / V35 rank_size[1] low dword
    registers: Sequence[int]     # +0x28: 17 legacy dwords / 10 V35 dwords
    mode_registers: Sequence[int]  # +0xA4: 6 legacy dwords; empty for V35
    layout: str = LAYOUT_LEGACY
    rank_sizes: Sequence[int] = ()  # V35 +0x50: four little-endian uint64
    dram_vendor_code: int | None = None  # V35 MR5 word (+0x98)

    # -- derived values -----------------------------------------------------

    @property
    def vendor_name(self) -> str:
        if self.vendor_code in VENDOR_NAMES:
            return VENDOR_NAMES[self.vendor_code]
        # A discrete DRAM entry has no eMMC CID.  Its vendor is encoded in
        # LPDDR4 MR5 (+0x98); record 15 of the attached MT6765 image is one.
        if (
            self.layout == LAYOUT_V35
            and self.vendor_code == 0
            and self.type_code < 0x100
            and self.dram_vendor_code in DRAM_VENDOR_NAMES
        ):
            return DRAM_VENDOR_NAMES[self.dram_vendor_code]
        # V49/V52/V54 have no eMMC vendor byte.  The observed +0x50 word is
        # the LPDDR MR5 vendor ID (1=Samsung, 6=Hynix, 0xFF=Micron).  If it is
        # not recognised, fall back to the UFS part-number prefix.
        if self.layout == LAYOUT_V49:
            if self.dram_vendor_code in DRAM_VENDOR_NAMES:
                return DRAM_VENDOR_NAMES[self.dram_vendor_code]
            return UFS_VENDOR_PREFIXES.get(self.part_number[:2], "Unknown")
        return "Unknown"

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type_code, "Invalid")

    @property
    def dram_type_name(self) -> str | None:
        """Low-nibble type; ``None`` reproduces the original "leave as-is" bug.

        Full type 0x205 is the only confirmed LPDDR4 (non-X) package.  A bare
        low nibble of 5 remains unmapped, preserving the original quirk that
        the existing tests exercise.
        """
        if self.type_code == 0x205:
            return "LPDDR4"
        return DRAM_TYPE_NAMES.get(self.type_code & 0x0F)

    @property
    def has_nand(self) -> bool:
        # Bit 0x100 alone also matches the 0x3xx uMCP(eUFS) types.  NAND is
        # only the 0x1xx family; 0x2xx is eMMC and 0x3xx is UFS.
        return (self.type_code & 0xF00) == 0x100

    @property
    def part_number(self) -> str:
        """Device part number.

        Legacy records reproduce the original behaviour: start at byte 3 of
        the 16-byte identifier buffer and loop through ``id_length`` inclusive,
        keeping only ASCII alphanumerics.

        V35 records expose the part-number bytes starting at byte 2.  In the
        eMMC CID layout byte 2 is the OEM/Application ID and bytes 3..8 are
        the six-byte product name.  Samsung/Sandisk put NUL in byte 2, while
        Hynix/Micron put a letter there (for example ``NG1J9R8``).  Reading
        ``[2:id_length]`` and dropping NUL/non-printable bytes recovers both
        forms.  Unlike the legacy alphanumeric filter, this keeps printable
        characters such as the ``>`` in ``JhB8aP>``.
        """
        if self.layout == LAYOUT_V35:
            end = min(max(self.id_length, 2), ID_BUFFER_SIZE)
            return "".join(
                chr(byte)
                for byte in self.id_field[2:end]
                if 0x20 <= byte <= 0x7E
            ).strip()

        if self.layout == LAYOUT_V49:
            # V49 stores the UFS part number directly at +0x08.  Micron's
            # 9-byte form starts with two binary UFS vendor bytes, which the
            # printable filter drops (for example 13 01 "NG1C12L").
            end = min(max(self.id_length, 0), ID_BUFFER_SIZE)
            return "".join(
                chr(byte)
                for byte in self.id_field[:end]
                if 0x20 <= byte <= 0x7E
            ).strip()

        end = min(max(self.id_length + 1, 3), ID_BUFFER_SIZE)
        return "".join(
            chr(byte) for byte in self.id_field[3:end] if _is_ascii_alnum(byte)
        )

    def _hex_bytes(self, data: bytes, count: int) -> str:
        count = min(max(count, 0), len(data))
        if count == 0:
            return ""
        return "0x" + "".join(f"{byte:02X}" for byte in data[:count])

    @property
    def id_hex(self) -> str:
        return self._hex_bytes(self.id_field, self.id_length)

    @property
    def fw_hex(self) -> str:
        return self._hex_bytes(self.fw_field, self.fw_length)

    @property
    def density_text(self) -> str:
        """Density in Mb, reproducing the original's split-rank formatting."""
        if self.layout in (LAYOUT_V35, LAYOUT_V49):
            low = self.rank_sizes[0] >> 17 if self.rank_sizes else 0
            high = self.rank_sizes[1] >> 17 if len(self.rank_sizes) > 1 else 0
        else:
            low = self.density_low >> 17
            high = self.density_high >> 17
        if high == 0:
            return str(low)
        return f"{low}+{high}"

    @classmethod
    def from_bytes(cls, raw: bytes) -> "EmiRecord":
        """Parse a legacy 188-byte record."""
        if len(raw) != RECORD_SIZE:
            raise EmiFormatError(
                f"record must be {RECORD_SIZE} bytes, got {len(raw)}"
            )
        return cls(
            raw=raw,
            type_code=struct.unpack_from("<i", raw, 0x04)[0],
            id_length=struct.unpack_from("<i", raw, 0x08)[0],
            fw_length=struct.unpack_from("<i", raw, 0x0C)[0],
            vendor_code=raw[0x10],
            id_field=raw[0x10:0x20],
            fw_field=raw[0x20:0x28],
            density_low=struct.unpack_from("<I", raw, 0x6C)[0],
            density_high=struct.unpack_from("<I", raw, 0x70)[0],
            registers=tuple(
                struct.unpack_from("<I", raw, 0x28 + 4 * i)[0]
                for i in range(REGISTER_COUNT)
            ),
            mode_registers=tuple(
                struct.unpack_from("<I", raw, 0xA4 + 4 * i)[0]
                for i in range(MODE_REG_COUNT)
            ),
        )

    @classmethod
    def from_bytes_v35(cls, raw: bytes) -> "EmiRecord":
        """Parse a modern 160-byte V35 record.

        Offsets are taken from ``EMIInfoV35.emi_cfg`` in MTK's
        ``emi_structures.h``: ten register dwords at +0x28, four 64-bit rank
        sizes at +0x50, and the LPDDR4 MR5 value at +0x98.  The mode-register
        block of the legacy layout does not exist in this structure.
        """
        if len(raw) != RECORD_SIZE_V35:
            raise EmiFormatError(
                f"V35 record must be {RECORD_SIZE_V35} bytes, got {len(raw)}"
            )
        rank_sizes = tuple(
            struct.unpack_from("<Q", raw, 0x50 + 8 * i)[0] for i in range(4)
        )
        return cls(
            raw=raw,
            type_code=struct.unpack_from("<i", raw, 0x04)[0],
            id_length=struct.unpack_from("<i", raw, 0x08)[0],
            fw_length=struct.unpack_from("<i", raw, 0x0C)[0],
            vendor_code=raw[0x10],
            id_field=raw[0x10:0x20],
            fw_field=raw[0x20:0x28],
            density_low=rank_sizes[0] & 0xFFFFFFFF,
            density_high=rank_sizes[1] & 0xFFFFFFFF,
            registers=tuple(
                struct.unpack_from("<I", raw, 0x28 + 4 * i)[0]
                for i in range(REGISTER_COUNT_V35)
            ),
            mode_registers=(),
            layout=LAYOUT_V35,
            rank_sizes=rank_sizes,
            # MTK's DA compares the whole 32-bit word at +0x98 with the MR5
            # value; only an exact value such as 0x000000FF is Micron.
            dram_vendor_code=struct.unpack_from("<I", raw, 0x98)[0],
        )

    @classmethod
    def from_bytes_v49(cls, raw: bytes) -> "EmiRecord":
        """Parse an 84-byte V49/V52/V54 record.

        MTK's ``EMIInfoV49`` contains type, ID length, a 16-byte UFS ID and
        four 64-bit rank sizes.  The preloader advances by 84 bytes per
        record (``sizeof(emi_len[21])``).  The remaining bytes after +0x38 are
        not part of the documented ``emi_cfg``; the observed +0x50 word is
        the LPDDR MR5 vendor ID, which the writer uses for vendor names.
        """
        if len(raw) != RECORD_SIZE_V49:
            raise EmiFormatError(
                f"V49 record must be {RECORD_SIZE_V49} bytes, got {len(raw)}"
            )

        rank_sizes = tuple(
            struct.unpack_from("<Q", raw, 0x18 + 8 * i)[0] for i in range(4)
        )
        return cls(
            raw=raw,
            type_code=struct.unpack_from("<i", raw, 0x00)[0],
            id_length=struct.unpack_from("<i", raw, 0x04)[0],
            fw_length=0,
            vendor_code=0,
            id_field=raw[0x08:0x18],
            fw_field=b"",
            density_low=rank_sizes[0] & 0xFFFFFFFF,
            density_high=rank_sizes[1] & 0xFFFFFFFF,
            registers=(),
            mode_registers=(),
            layout=LAYOUT_V49,
            rank_sizes=rank_sizes,
            dram_vendor_code=struct.unpack_from("<I", raw, 0x50)[0],
        )


#: Vendor byte -> vendor label (case 0x42C650 in the original).
#: The additional IDs come from MTKPreloaderParser's ``get_card_mfr_id``.
VENDOR_NAMES = {
    0x02: "Sandisk_New",
    0x11: "Toshiba",
    0x13: "Micron",
    0x15: "Samsung",
    0x45: "Sandisk",
    0x70: "Kingston",
    0x74: "Transcend",
    0x88: "Foresee",
    0x8F: "UNIC",
    0x90: "Hynix",
    0xF4: "Biwin",
    0xFE: "Micron",
}

#: UFS part-number prefixes used by MTKPreloaderParser's ``PraseCID``.  These
#: are only a fallback for V49 records whose MR5 word is not recognised.
UFS_VENDOR_PREFIXES = {
    "KM": "Samsung",
    "H9": "Hynix",
    "MT": "Micron",
    "Z": "Micron",
    "TH": "Toshiba",
}

#: Full package/type code (case 0x42C2E0 in the original), extended with the
#: modern codes from MTKPreloaderParser's ``get_dram_type``.  The source spells
#: 0x206 as "MCP(eMMC+LPDR4X)"; it is normalised to LPDDR4X here.
TYPE_NAMES = {
    1: "Discrete DDR1",
    2: "Discrete LPDDR2",
    3: "Discrete LPDDR3",
    4: "Discrete PCDDR3",
    6: "Discrete LPDDR4X",
    # Full type 8 is the discrete counterpart of 0x308 (uMCP LPDDR5); the
    # low-nibble map below already confirms 8 = LPDDR5.
    8: "Discrete LPDDR5",
    0x101: "MCP(NAND+DDR1)",
    0x102: "MCP(NAND+LPDDR2)",
    0x103: "MCP(NAND+LPDDR3)",
    0x104: "MCP(NAND+PCDDR3)",
    0x201: "MCP(eMMC+DDR1)",
    0x202: "MCP(eMMC+LPDDR2)",
    0x203: "MCP(eMMC+LPDDR3)",
    0x204: "MCP(eMMC+PCDDR3)",
    0x205: "MCP(eMMC+LPDDR4)",
    0x206: "MCP(eMMC+LPDDR4X)",
    0x306: "uMCP(eUFS+LPDDR4X)",
    0x308: "uMCP(eUFS+LPDDR5)",
}

#: Low-nibble DRAM type (case 0x42C280 in the original).
DRAM_TYPE_NAMES = {
    1: "DDR1",
    2: "LPDDR2",
    3: "LPDDR3",
    4: "PCDDR3",
    6: "LPDDR4X",
    8: "LPDDR5",
}

#: LPDDR4 MR5 manufacturer ID -> vendor.  These are exact 32-bit table
#: values (MTK's DA compares the whole word at +0x98).  JEP166E-derived
#: assignments: 0x01 Samsung, 0x05 Nanya, 0x06 SK Hynix, 0x13 CXMT,
#: 0xFF Micron.  A combined word such as 0x0000FF01 is intentionally not
#: mapped: the DA itself rejects it as a vendor match.
DRAM_VENDOR_NAMES = {
    0x01: "Samsung",
    0x05: "Nanya",
    0x06: "Hynix",
    0x13: "CXMT",
    0xFF: "Micron",
}


def _find_rominfo(data: bytes) -> int:
    """Find an ``AND_ROMINFO_v`` block whose major version is 2.

    The attached MT6765 image uses ``02 00 02 00`` (2.2), while the original
    executable's exact 20-byte signature only accepts 2.0.  Matching the
    stable 16-byte prefix and checking the major uint16 accepts both.
    """
    position = 0
    while True:
        position = data.find(ROMINFO_PREFIX, position)
        if position < 0:
            return -1
        version_position = position + len(ROMINFO_PREFIX)
        if version_position + 4 <= len(data):
            major = struct.unpack_from("<H", data, version_position)[0]
            if major == ROMINFO_VERSION_MAJOR:
                return position
        position += 1


def _loader_version(data: bytes, mtk_position: int) -> int | None:
    """Return the ``MTK_BLOADER_INFO_vNN`` version preceding MTK_BIN."""
    window_start = max(0, mtk_position - 0x100)
    position = data.rfind(
        MTK_BLOADER_INFO_PREFIX, window_start, mtk_position
    )
    if position < 0:
        return None
    digits_position = position + len(MTK_BLOADER_INFO_PREFIX)
    digits = data[digits_position:digits_position + 2]
    if len(digits) != 2 or not digits.isdigit():
        return None
    return int(digits)


def _record_stride(layout: str) -> int:
    if layout == LAYOUT_V35:
        return RECORD_SIZE_V35
    if layout == LAYOUT_V49:
        return RECORD_SIZE_V49
    return RECORD_SIZE


def _is_blank_v35_record(record: EmiRecord) -> bool:
    """True for an all-zero padding slot (not the type-6 DRAM entry)."""
    return record.type_code == 0 and not any(record.raw[4:])


def _is_blank_v49_record(record: EmiRecord) -> bool:
    """True for an all-zero V49/V52/V54 padding slot."""
    return record.type_code == 0 and not any(record.raw[4:])


def _candidate_score(
    data: bytes, records_start: int, count: int, layout: str
) -> int:
    """Score a candidate record layout for header-less legacy files.

    A score of -1 means the records do not even fit.  Otherwise every record
    contributes points for plausible type/length/vendor fields.  The caller
    keeps the legacy layout on a tie, which preserves the original tool's
    behaviour for ambiguous single-record files.
    """
    stride = _record_stride(layout)
    if count <= 0 or records_start + count * stride > len(data):
        return -1

    score = 0
    for index in range(count):
        raw = data[
            records_start + index * stride:
            records_start + (index + 1) * stride
        ]
        id_length = struct.unpack_from("<i", raw, 0x08)[0]
        fw_length = struct.unpack_from("<i", raw, 0x0C)[0]
        type_code = struct.unpack_from("<i", raw, 0x04)[0]
        vendor = raw[0x10]

        if not 0 <= id_length <= ID_BUFFER_SIZE:
            return -1
        if not 0 <= fw_length <= FW_ID_BUFFER_SIZE:
            return -1
        if not 0 <= type_code <= 0xFFFF:
            return -1

        score += 1
        if vendor in VENDOR_NAMES or vendor == 0:
            score += 1
        if type_code != 0:
            score += 1
    return score


def _choose_layout(data: bytes, records_start: int, count: int) -> str:
    legacy_score = _candidate_score(
        data, records_start, count, LAYOUT_LEGACY
    )
    v35_score = _candidate_score(data, records_start, count, LAYOUT_V35)
    if v35_score > legacy_score:
        return LAYOUT_V35
    return LAYOUT_LEGACY


@dataclass
class EmiState:
    """Global state that the original executable keeps between input files.

    The original does not reset these fields at the start of a file.  If a
    later file lacks one of the signatures, the previous values are reused.
    """

    platform: str = ""
    count: int = 0
    records: List[EmiRecord] = field(default_factory=list)

    def load_bytes(self, data: bytes) -> None:
        """Scan ``data`` and update the persistent state in place."""

        # ---- AND_ROMINFO_v -------------------------------------------------
        rom_position = _find_rominfo(data)
        if rom_position >= 0:
            start = rom_position + len(ROMINFO_PREFIX) + 4
            end = start + PLATFORM_SIZE
            if end > len(data):
                raise EmiFormatError(
                    "truncated AND_ROMINFO_v block: platform name is incomplete"
                )
            # latin-1 preserves the original raw bytes one-to-one.
            self.platform = data[start:end].decode("latin-1")

        # ---- MTK_BIN -------------------------------------------------------
        mtk_position = data.find(SIG_MTK_BIN)
        if mtk_position >= 0:
            start = mtk_position + len(SIG_MTK_BIN)
            if start + 4 > len(data):
                raise EmiFormatError("truncated MTK_BIN block: missing device count")

            self.count = struct.unpack_from("<i", data, start)[0]

            if self.count > 0:
                records_start = start + 4
                version = _loader_version(data, mtk_position)
                if version in V35_LAYOUT_VERSIONS:
                    layout = LAYOUT_V35
                elif version in V49_LAYOUT_VERSIONS:
                    layout = LAYOUT_V49
                elif version is not None:
                    # v10 and the other older layouts keep the original
                    # 188-byte behaviour, even though their on-disk config
                    # structure is smaller.
                    layout = LAYOUT_LEGACY
                else:
                    layout = _choose_layout(
                        data, records_start, self.count
                    )

                stride = _record_stride(layout)
                available = len(data) - records_start
                if self.count > available // stride:
                    raise EmiFormatError(
                        "truncated MTK_BIN block: "
                        f"expected {self.count} {layout} records "
                        f"({self.count * stride} bytes), "
                        f"but only {available} bytes remain"
                    )

                if layout == LAYOUT_V35:
                    records = [
                        EmiRecord.from_bytes_v35(
                            data[
                                records_start + i * stride:
                                records_start + (i + 1) * stride
                            ]
                        )
                        for i in range(self.count)
                    ]
                    # Some images pad the table with all-zero slots.  They are
                    # not devices and would otherwise produce an "Invalid" row.
                    records = [
                        record for record in records
                        if not _is_blank_v35_record(record)
                    ]
                    self.records = records
                    self.count = len(records)
                elif layout == LAYOUT_V49:
                    records = [
                        EmiRecord.from_bytes_v49(
                            data[
                                records_start + i * stride:
                                records_start + (i + 1) * stride
                            ]
                        )
                        for i in range(self.count)
                    ]
                    records = [
                        record for record in records
                        if not _is_blank_v49_record(record)
                    ]
                    self.records = records
                    self.count = len(records)
                else:
                    self.records = [
                        EmiRecord.from_bytes(
                            data[
                                records_start + i * stride:
                                records_start + (i + 1) * stride
                            ]
                        )
                        for i in range(self.count)
                    ]
            # If count <= 0 the original leaves the old record array untouched
            # but main() refuses to write a file, so we do the same.

    def load_file(self, path: str) -> None:
        with open(path, "rb") as handle:
            self.load_bytes(handle.read())
