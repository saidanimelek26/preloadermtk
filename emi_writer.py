"""Excel writer for the EMI extractor clone.

The original tool loads ``template.xls`` (BIFF8), writes into the first
worksheet only, and saves the result next to the input file.  This module
uses xlrd/xlutils/xlwt to keep the template sheets, merged cells, column
widths and cell styles as close as the library allows.
"""

from __future__ import annotations

import copy
import os

import xlrd
import xlwt
from xlutils.filter import XLRDReader, XLWTWriter, process

from emi_parser import EmiState


class EmiWriteError(RuntimeError):
    """Raised when the template or output workbook cannot be handled."""


#: Column layout of the first worksheet.  Column 9 (J) and 26/27 (AA/AB)
#: are deliberately absent: the original never writes them.
REGISTER_COLUMNS = (8, *range(10, 26))
MODE_REGISTER_COLUMNS = tuple(range(29, 35))

PLATFORM_CELL = (0, 8)          # I1
FIRST_DATA_ROW = 3              # 0-based -> Excel row 4
DRAM_TYPE_COLUMN = 28           # AC
NAND_MARKER_COLUMN = 7          # H
NAND_MARKER_TEXT = "?"


def _hex32(value: int) -> str:
    """Format a dword exactly like the original's ``0x%.8X``."""
    return f"0x{value & 0xFFFFFFFF:08X}"


def _ascii_upper(text: str) -> str:
    """Free Pascal ``UpperCase`` behaviour for the raw platform bytes."""
    return "".join(
        chr(ord(char) - 32) if "a" <= char <= "z" else char for char in text
    )


def _ascii_lower(text: str) -> str:
    """Free Pascal ``LowerCase`` behaviour for the raw platform bytes."""
    return "".join(
        chr(ord(char) + 32) if "A" <= char <= "Z" else char for char in text
    )


def find_output_path(input_path: str, platform: str) -> str:
    """Reproduce the original output-name collision logic.

    ``MemoryDeviceList_<PLATFORM>.xls`` in the input directory.  The original
    upper-cases the platform for the file name, even if the six raw bytes were
    mixed-case.  On a collision it tries ``(0)``, ``(1)``, ... in that order.
    """
    directory = os.path.dirname(input_path)
    base_name = f"MemoryDeviceList_{_ascii_upper(platform)}"

    candidate = (
        os.path.join(directory, base_name + ".xls")
        if directory
        else base_name + ".xls"
    )
    if not os.path.exists(candidate):
        return candidate

    index = 0
    while True:
        name = f"{base_name}({index}).xls"
        candidate = os.path.join(directory, name) if directory else name
        if not os.path.exists(candidate):
            return candidate
        index += 1


def _load_template(template_path: str):
    """Load the template and return (xlrd book, xlwt book, style list)."""
    if not os.path.isfile(template_path):
        raise EmiWriteError(
            f"template not found: {template_path} "
            "(template.xls must sit next to the script/executable)"
        )

    try:
        # xlrd 1.2.x is required: xlrd 2.x removed formatting_info.
        read_book = xlrd.open_workbook(template_path, formatting_info=True)
        writer = XLWTWriter()
        process(XLRDReader(read_book, os.path.basename(template_path)), writer)
        write_book = writer.output[0][1]
    except Exception as exc:  # pragma: no cover - defensive wrapper
        raise EmiWriteError(
            f"cannot load template '{template_path}': {exc}"
        ) from exc

    if read_book.nsheets == 0:
        raise EmiWriteError(f"template has no worksheets: {template_path}")
    # ``style_list`` is indexed by the template's XF index, i.e. the values
    # returned by ``sheet.cell_xf_index(row, col)``.
    return read_book, write_book, writer.style_list


def _normalise_styles(styles) -> None:
    """Apply the style normalisation that fpspreadsheet performs on save.

    The original output unlocks every cell and resolves automatic font
    colours to black.  Fill palettes are remapped, but the resulting RGB
    colours are unchanged; xlwt keeps the template palette, so the visual
    result is the same without remapping indices here.
    """
    for style in styles:
        if style is None:
            continue
        style.protection.cell_locked = 0
        style.protection.formula_hidden = 0
        if style.font.colour_index in (64, 32767):
            style.font.colour_index = 0
        if style.pattern.pattern == 0:
            # Unused fill colours: the original writes 0/0 instead of the
            # template's "automatic" 64/65 placeholders.
            style.pattern.pattern_fore_colour = 0
            style.pattern.pattern_back_colour = 0


def _default_data_style():
    """The style fpspreadsheet gives to newly created cells.

    It is the xlwt default (Arial 10, left/bottom, no wrap), except that the
    font colour is explicit black and the cell is unlocked.
    """
    style = xlwt.XFStyle()
    style.font.colour_index = 0
    style.protection.cell_locked = 0
    style.protection.formula_hidden = 0
    style.pattern.pattern_fore_colour = 0
    style.pattern.pattern_back_colour = 0
    return style


def _blank_cell_style(style):
    """Style for a template cell that exists only as a formatted blank.

    The density column (D) is such a cell.  fpspreadsheet keeps its alignment
    and font but drops the unused fill definition and protection.
    """
    result = copy.deepcopy(style)
    result.pattern.pattern = 0
    result.pattern.pattern_fore_colour = 0
    result.pattern.pattern_back_colour = 0
    return result


def _style_for_cell(read_sheet, styles, default_style, row: int, column: int):
    """Choose the cell style following the original's write behaviour.

    * existing text cells (for example I1) keep their template style;
    * formatted blank cells (for example the density column D) keep their
      font/alignment but lose the unused fill;
    * completely empty cells (the rest of the data area, and rows beyond the
      template) are written with fpspreadsheet's default style.
    """
    if row < read_sheet.nrows and column < read_sheet.ncols:
        cell_type = read_sheet.cell_type(row, column)
        if cell_type == xlrd.XL_CELL_EMPTY:
            return default_style
        if cell_type == xlrd.XL_CELL_BLANK:
            return _blank_cell_style(
                styles[read_sheet.cell_xf_index(row, column)]
            )
        return styles[read_sheet.cell_xf_index(row, column)]
    return default_style


def write_workbook(state: EmiState, input_path: str, template_path: str) -> str:
    """Write one ``MemoryDeviceList_*.xls`` and return its path."""
    read_book, write_book, styles = _load_template(template_path)
    _normalise_styles(styles)
    # fpspreadsheet draws the template's borders with its default dark-grey
    # line colour (RGB 58,57,53).  The template uses palette index 59 for
    # those borders; xlwt's default palette maps index 59 to olive, so align
    # that entry with the original output.
    write_book.set_colour_RGB(59, 58, 57, 53)
    default_style = _default_data_style()
    read_sheet = read_book.sheet_by_index(0)

    try:
        write_sheet = write_book.get_sheet(0)
    except Exception as exc:  # pragma: no cover - template issue
        raise EmiWriteError(f"template has no first worksheet: {exc}") from exc

    # fpspreadsheet resets every column's default format to the workbook
    # default (XF 15 in the original output).  Empty cells inherit it; cells
    # with their own format or value are unaffected.
    for sheet_index in range(read_book.nsheets):
        read_sheet_for_defaults = read_book.sheet_by_index(sheet_index)
        write_sheet_for_defaults = write_book.get_sheet(sheet_index)
        write_sheet_for_defaults.set_row_default_height(300)
        for column in read_sheet_for_defaults.colinfo_map:
            write_sheet_for_defaults.col(column).set_style(default_style)
        # Empty cells inherit the row format when one is present.  fpspreadsheet
        # clears the row-level format as well, leaving only the default.
        for row_index, row_info in read_sheet_for_defaults.rowinfo_map.items():
            row_object = write_sheet_for_defaults.row(row_index)
            row_object.set_style(default_style)
            # Rows with a custom height in the template keep it (header rows,
            # and the template's one data row with an explicit 255).  Rows
            # that only inherited the template default height use
            # fpspreadsheet's 300-twip default instead.
            if not row_info.height_mismatch:
                row_object.height = 300
                row_object.height_mismatch = 0

    # The original renames worksheet 0 to the platform name, lower-cased
    # (e.g. "ABC123" -> "abc123", empty platform -> "").
    write_sheet.name = _ascii_lower(state.platform)

    def emit(row: int, column: int, value: str) -> str:
        write_sheet.write(
            row,
            column,
            value,
            _style_for_cell(read_sheet, styles, default_style, row, column),
        )
        return value

    # I1 = platform name.  The original upper-cases it for every cell value
    # and for the output file name; only the worksheet name is lower-cased.
    platform_upper = _ascii_upper(state.platform)
    emit(*PLATFORM_CELL, platform_upper)

    board_id = platform_upper + "_EVB"

    for index in range(state.count):
        record = state.records[index]
        row = FIRST_DATA_ROW + index
        scratch = ""

        scratch = emit(row, 0, record.vendor_name)
        scratch = emit(row, 1, record.part_number)
        scratch = emit(row, 2, record.type_name)
        scratch = emit(row, 3, record.density_text)
        scratch = emit(row, 4, board_id)
        scratch = emit(row, 5, record.id_hex)
        scratch = emit(row, 6, record.fw_hex)

        if record.has_nand:
            emit(row, NAND_MARKER_COLUMN, NAND_MARKER_TEXT)

        # Registers 0..16 -> columns I, K, L, ..., Z (J is skipped).
        # V35 records only carry ten register dwords, and no mode registers;
        # unavailable cells are written blank instead of inventing values.
        for offset, column in enumerate(REGISTER_COLUMNS):
            value = (
                _hex32(record.registers[offset])
                if offset < len(record.registers)
                else ""
            )
            scratch = emit(row, column, value)

        # Column AC.  The original leaves the previous scratch value in place
        # when the low nibble is not 1..4; we reproduce that quirk for legacy
        # records.  For V35 the scratch is blank when no mapping exists.
        dram_type = record.dram_type_name
        if dram_type is not None:
            scratch = dram_type
        scratch = emit(row, DRAM_TYPE_COLUMN, scratch)

        # MODE_REG1, 2, 3, 5, 10, 63 -> AD..AI (legacy layout only).
        for offset, column in enumerate(MODE_REGISTER_COLUMNS):
            value = (
                _hex32(record.mode_registers[offset])
                if offset < len(record.mode_registers)
                else ""
            )
            scratch = emit(row, column, value)

    # fpspreadsheet saves the data area with a 300-twip (15 pt) row height;
    # the template itself uses 255 for those rows.  Header rows keep 345.
    write_sheet.set_row_default_height(300)
    last_row = max(read_sheet.nrows, FIRST_DATA_ROW + state.count)
    for row_index in range(read_sheet.nrows, last_row):
        row_object = write_sheet.row(row_index)
        row_object.set_style(default_style)
        row_object.height = 300
        row_object.height_mismatch = 0

    output_path = find_output_path(input_path, state.platform)

    try:
        write_book.save(output_path)
    except Exception as exc:
        raise EmiWriteError(f"cannot save output '{output_path}': {exc}") from exc

    return output_path
