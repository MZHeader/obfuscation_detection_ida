"""Dockable Qt-backed results table.

One row per function; each row aggregates every heuristic that fired on it.
Double-clicking a row jumps IDA to that function.

The Qt bindings shipping with IDA differ across versions (PyQt5 on 7.x/8.x,
PySide6 on 9.x). We try each import in order and disable the view if
neither is available; the plugin still tags functions and prints to the
Output window in that case.
"""

import ida_kernwin

_QT_OK = False
_QtCore = None
_QtWidgets = None

for _mod in ("PySide6", "PySide2", "PyQt5"):
    try:
        if _mod == "PySide6":
            from PySide6 import QtCore as _QtCore, QtWidgets as _QtWidgets
        elif _mod == "PySide2":
            from PySide2 import QtCore as _QtCore, QtWidgets as _QtWidgets
        else:
            from PyQt5 import QtCore as _QtCore, QtWidgets as _QtWidgets
        _QT_OK = True
        break
    except ImportError:
        continue


_COLUMNS = ("Hits", "Heuristics", "Function", "Address", "Scores", "Sites")

_SCORE_UNITS = {
    "state_machine_score": "flatness",
    "cyclomatic_complexity": "cc",
    "avg_instructions_per_block": "insns/block",
    "uncommon_sequences_score": "uncommon",
    "num_callers": "callers",
    "num_loops": "loops",
    "num_irreducible_loops": "irreducible loops",
    "num_duplicate_subgraphs": "duplicates",
    "num_mba_instructions": "MBA ops",
    "fragmentation_ratio": "blocks/branch",
}

_TAG_PREFIX = "Heuristic: "

_INSTANCE = None


_SORT_ROLE = None


def _make_numeric_item_class():
    global _SORT_ROLE
    if _SORT_ROLE is None:
        _SORT_ROLE = _QtCore.Qt.UserRole + 1

    class _NumericItem(_QtWidgets.QTableWidgetItem):
        def __lt__(self, other):
            a = self.data(_SORT_ROLE)
            b = other.data(_SORT_ROLE) if isinstance(other, _QtWidgets.QTableWidgetItem) else None
            if a is not None and b is not None:
                try:
                    return float(a) < float(b)
                except (TypeError, ValueError):
                    pass
            return self.text() < (other.text() if hasattr(other, "text") else "")

    return _NumericItem


_NUMERIC_ITEM_CLASS = None


def _numeric_item(display_text, sort_value):
    global _NUMERIC_ITEM_CLASS
    if not _QT_OK:
        return None
    if _NUMERIC_ITEM_CLASS is None:
        _NUMERIC_ITEM_CLASS = _make_numeric_item_class()
    item = _NUMERIC_ITEM_CLASS(display_text)
    if sort_value is not None:
        item.setData(_SORT_ROLE, float(sort_value))
    return item


def _short_tag(tag_type):
    if tag_type.startswith(_TAG_PREFIX):
        return tag_type[len(_TAG_PREFIX):]
    return tag_type


def _score_display(finding, extra_key):
    if not extra_key or extra_key not in finding:
        return ""
    raw = finding[extra_key]
    if isinstance(raw, float):
        value_text = "%.3f" % raw
    elif isinstance(raw, int):
        value_text = str(raw)
    else:
        value_text = str(raw)
    unit = _SCORE_UNITS.get(extra_key, "")
    return ("%s %s" % (value_text, unit)).strip()


class _ResultsForm(ida_kernwin.PluginForm):
    """Dockable widget listing every function that fired any heuristic."""

    def __init__(self):
        super(_ResultsForm, self).__init__()
        self._parent = None
        self._table = None
        self._rows_by_ea = {}

    def OnCreate(self, form):
        if not _QT_OK:
            self._parent = None
            return
        if hasattr(self, "FormToPyQtWidget"):
            self._parent = self.FormToPyQtWidget(form)
        elif hasattr(self, "FormToPySideWidget"):
            self._parent = self.FormToPySideWidget(form)
        else:
            self._parent = None
            return
        if self._parent is None:
            return
        layout = _QtWidgets.QVBoxLayout(self._parent)
        self._table = _QtWidgets.QTableWidget(self._parent)
        self._table.setColumnCount(len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setSelectionBehavior(_QtWidgets.QAbstractItemView.SelectRows)
        self._table.setEditTriggers(_QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(True)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(_QtWidgets.QHeaderView.Interactive)
        self._table.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)
        self._parent.setLayout(layout)
        self._repopulate()

    def OnClose(self, form):
        self._parent = None
        self._table = None

    def _repopulate(self):
        if self._table is None:
            return
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for row in self._rows_by_ea.values():
            self._append_row(row)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, _QtCore.Qt.DescendingOrder)

    def _find_visual_row(self, ea):
        for r in range(self._table.rowCount()):
            addr_item = self._table.item(r, 3)
            if addr_item is None:
                continue
            if addr_item.data(_QtCore.Qt.UserRole) == ea:
                return r
        return -1

    def _append_row(self, row):
        r = self._table.rowCount()
        self._table.insertRow(r)
        self._write_row_cells(r, row)

    def _write_row_cells(self, r, row):
        hits = len(row["findings"])
        heurs = ", ".join(sorted(_short_tag(t) for t in row["findings"].keys()))
        scores = " | ".join(
            "%s=%s" % (_short_tag(t), d["score_display"])
            for t, d in sorted(row["findings"].items())
            if d.get("score_display")
        )
        total_sites = sum(d.get("sites_count", 0) for d in row["findings"].values())

        hits_item = _numeric_item(str(hits), hits)
        heur_item = _QtWidgets.QTableWidgetItem(heurs)
        name_item = _QtWidgets.QTableWidgetItem(row["name"])
        addr_item = _numeric_item(row["address"], row["ea"])
        addr_item.setData(_QtCore.Qt.UserRole, row["ea"])
        score_item = _QtWidgets.QTableWidgetItem(scores)
        sites_item = _numeric_item(str(total_sites) if total_sites else "", total_sites)

        self._table.setItem(r, 0, hits_item)
        self._table.setItem(r, 1, heur_item)
        self._table.setItem(r, 2, name_item)
        self._table.setItem(r, 3, addr_item)
        self._table.setItem(r, 4, score_item)
        self._table.setItem(r, 5, sites_item)

    def _refresh_row(self, ea):
        if self._table is None:
            return
        row = self._rows_by_ea.get(ea)
        r = self._find_visual_row(ea)
        if row is None:
            if r >= 0:
                self._table.removeRow(r)
            return
        if r < 0:
            self._append_row(row)
        else:
            self._write_row_cells(r, row)

    def _on_double_click(self, index):
        addr_item = self._table.item(index.row(), 3)
        ea = addr_item.data(_QtCore.Qt.UserRole) if addr_item is not None else None
        if ea is not None:
            ida_kernwin.jumpto(int(ea))

    def add_finding(self, finding, tag_type, extra_key=None):
        address = finding.get("address")
        if not address:
            return
        ea = int(address, 16)
        anchors = list(finding.get("anchor_addresses", []) or [])
        detail = {
            "score_display": _score_display(finding, extra_key),
            "sites_count": len(anchors),
            "first_anchor": anchors[0] if anchors else None,
        }
        row = self._rows_by_ea.get(ea)
        if row is None:
            row = {
                "ea": ea,
                "address": address,
                "name": finding.get("name", ""),
                "findings": {},
            }
            self._rows_by_ea[ea] = row
        else:
            if not row["name"] and finding.get("name"):
                row["name"] = finding["name"]
        row["findings"][tag_type] = detail

        if self._table is not None:
            self._table.setSortingEnabled(False)
            self._refresh_row(ea)
            self._table.setSortingEnabled(True)

    def clear_heuristic(self, tag_type):
        affected = []
        for ea, row in list(self._rows_by_ea.items()):
            if tag_type in row["findings"]:
                del row["findings"][tag_type]
                if not row["findings"]:
                    del self._rows_by_ea[ea]
                affected.append(ea)
        if self._table is None:
            return
        self._table.setSortingEnabled(False)
        for ea in affected:
            self._refresh_row(ea)
        self._table.setSortingEnabled(True)

    def begin_batch(self, tag_type):
        self.clear_heuristic(tag_type)

    def end_batch(self):
        if self._table is not None:
            self._table.resizeColumnsToContents()


def show():
    if not _QT_OK:
        print("[obfdet] Results View unavailable: no Qt bindings found.")
        return None
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = _ResultsForm()
    _INSTANCE.Show("Obfuscation Detection Results", options=ida_kernwin.PluginForm.WOPN_PERSIST)
    return _INSTANCE


def results_view():
    return _INSTANCE
