"""Dockable Qt-backed results table.

The view accumulates findings across every heuristic invocation in a
session. Double-clicking a row jumps IDA to that function or instruction.

The Qt bindings shipping with IDA differ across versions (PyQt5 on 7.x/8.x,
PySide6 on 9.x). We try each import in order and disable the view if
neither is available — the plugin still tags functions and prints to the
Output window in that case.
"""

import ida_kernwin

_QT_OK = False
_QtCore = None
_QtWidgets = None

# IDA 9 ships PySide6; IDA 8 ships PySide2; PyQt5 is only used as a last-ditch
# fallback since IDA 9 warns about it. Try Qt bindings in that preference order.
for _mod in ("PySide6", "PySide2", "PyQt5"):
    try:
        if _mod == "PySide6":
            from PySide6 import QtCore as _QtCore, QtWidgets as _QtWidgets  # noqa: F401
        elif _mod == "PySide2":
            from PySide2 import QtCore as _QtCore, QtWidgets as _QtWidgets  # noqa: F401
        else:
            from PyQt5 import QtCore as _QtCore, QtWidgets as _QtWidgets  # noqa: F401
        _QT_OK = True
        break
    except ImportError:
        continue


_COLUMNS = ("Heuristic", "Function", "Address", "Score", "Sites")

_INSTANCE = None


_SORT_ROLE = None  # populated once Qt is loaded


def _make_numeric_item_class():
    """Lazily build a QTableWidgetItem subclass with a numeric __lt__.

    Sort key lives in Qt.UserRole+1. Rows without a numeric key fall back to
    string comparison so partially-populated columns still sort sensibly.
    """
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


class _ResultsForm(ida_kernwin.PluginForm):
    """Dockable widget listing every finding produced this session."""

    def __init__(self):
        super(_ResultsForm, self).__init__()
        self._parent = None
        self._table = None
        self._rows = []  # list of dicts

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
        # Keep _rows and _INSTANCE so re-opening restores state. Just drop UI refs.
        self._parent = None
        self._table = None

    def _repopulate(self):
        if self._table is None:
            return
        self._table.setRowCount(0)
        for row in self._rows:
            self._append_row(row)

    def _append_row(self, row):
        r = self._table.rowCount()
        self._table.insertRow(r)

        heur_item = _QtWidgets.QTableWidgetItem(row["heuristic"])
        name_item = _QtWidgets.QTableWidgetItem(row["name"])
        addr_item = _numeric_item(row["address"], row["ea"])
        addr_item.setData(_QtCore.Qt.UserRole, row["ea"])
        score_item = _numeric_item(row["score_display"], row["score_sort"])
        sites_item = _numeric_item(row["sites_display"], row["sites_sort"])
        if row.get("first_anchor") is not None:
            sites_item.setData(_QtCore.Qt.UserRole, row["first_anchor"])

        self._table.setItem(r, 0, heur_item)
        self._table.setItem(r, 1, name_item)
        self._table.setItem(r, 2, addr_item)
        self._table.setItem(r, 3, score_item)
        self._table.setItem(r, 4, sites_item)

    def _on_double_click(self, index):
        col = index.column()
        item = self._table.item(index.row(), col)
        ea = item.data(_QtCore.Qt.UserRole) if item is not None else None
        if ea is None:
            # fall back to the address column
            ea_item = self._table.item(index.row(), 2)
            ea = ea_item.data(_QtCore.Qt.UserRole) if ea_item is not None else None
        if ea is not None:
            ida_kernwin.jumpto(int(ea))

    # ---- public API used by heuristics ----

    def add_finding(self, finding, tag_type, extra_key=None):
        anchors = list(finding.get("anchor_addresses", []) or [])
        score_display = ""
        score_sort = None
        if extra_key and extra_key in finding:
            raw = finding[extra_key]
            if isinstance(raw, float):
                score_display = "%.3f" % raw
                score_sort = raw
            elif isinstance(raw, int):
                score_display = str(raw)
                score_sort = raw
            else:
                score_display = str(raw)
                try:
                    score_sort = float(raw)
                except (TypeError, ValueError):
                    score_sort = None
        row = {
            "heuristic": tag_type,
            "name": finding.get("name", ""),
            "address": finding.get("address", ""),
            "ea": int(finding["address"], 16) if finding.get("address") else 0,
            "score_display": score_display,
            "score_sort": score_sort,
            "sites_display": str(len(anchors)) if anchors else "",
            "sites_sort": len(anchors) if anchors else 0,
            "first_anchor": anchors[0] if anchors else None,
        }
        self._rows.append(row)
        if self._table is not None:
            self._table.setSortingEnabled(False)
            self._append_row(row)
            self._table.setSortingEnabled(True)

    def clear_heuristic(self, tag_type):
        self._rows = [r for r in self._rows if r["heuristic"] != tag_type]
        self._repopulate()

    def begin_batch(self, tag_type):
        """Drop prior findings for `tag_type` so the view mirrors a fresh run."""
        self.clear_heuristic(tag_type)

    def end_batch(self):
        if self._table is not None:
            self._table.resizeColumnsToContents()


def show():
    """Open (or focus) the results dock."""
    if not _QT_OK:
        print("[obfdet] Results View unavailable: no Qt bindings found.")
        return None
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = _ResultsForm()
    _INSTANCE.Show("Obfuscation Detection Results", options=ida_kernwin.PluginForm.WOPN_PERSIST)
    return _INSTANCE


def results_view():
    """Return the live view (if the user has opened it), else None.

    Heuristics call this to record findings; if the view isn't open we
    return None so `_apply` skips the append cheaply.
    """
    return _INSTANCE
