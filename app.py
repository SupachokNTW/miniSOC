"""MiniSOC 2.4 - local Windows endpoint monitor with response actions (PySide6 desktop UI)."""
import json
import platform
import sys

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem,
    QListWidgetItem, QStyle, QSystemTrayIcon, QTextEdit, QVBoxLayout, QWidget,
)

import database as db
import event_catalog as cat
import response
from detection import ALLOW_FIELDS, RULE_EVENTS

# ----------------------------------------------------------------------------- theme
PALETTE = {
    '@bg': '#0d1117', '@panel': '#161b22', '@panel2': '#1c232d', '@border': '#2b3440',
    '@text': '#e6edf3', '@muted': '#8b949e', '@hover': '#222b37',
    '@accenthover': '#5b9cff', '@accentbg': '#16294a', '@accent': '#3b82f6',
}
QSS = '''
QWidget{background:@bg;color:@text;font-family:"Segoe UI","Inter","Noto Sans",sans-serif;font-size:13px}
QLabel{background:transparent}
#Sidebar{background:@panel;border-right:1px solid @border}
#Brand{font-size:18px;font-weight:700;padding:20px 18px 0 18px}
#BrandSub{color:@muted;font-size:11px;padding:2px 18px 16px 18px}
QListWidget#Nav{background:transparent;border:0;outline:0;padding:4px 8px}
QListWidget#Nav::item{padding:10px 12px;margin:2px 0;border-radius:8px;color:@muted}
QListWidget#Nav::item:hover{background:@hover;color:@text}
QListWidget#Nav::item:selected{background:@accentbg;color:@accenthover;font-weight:600}
#SideFoot{color:@muted;font-size:11px;padding:12px 18px}
#Header{background:@panel;border-bottom:1px solid @border}
#PageTitle{font-size:19px;font-weight:600}
#Muted{color:@muted}
#Card{background:@panel;border:1px solid @border;border-radius:12px}
#CardLabel{color:@muted;font-size:12px}
#Section{font-size:14px;font-weight:600;padding-top:6px}
#Detail{font-family:"Cascadia Mono","Consolas","DejaVu Sans Mono",monospace;font-size:12px}
QPushButton{background:@accent;color:white;border:0;padding:8px 16px;border-radius:8px;font-weight:600}
QPushButton:hover{background:@accenthover}
QPushButton:disabled{background:@border;color:@muted}
QPushButton[kind="ghost"]{background:transparent;border:1px solid @border;color:@text}
QPushButton[kind="ghost"]:hover{background:@hover}
QPushButton[kind="ghost"]:disabled{color:@muted;background:transparent}
QPushButton[kind="danger"]{background:#da3633}
QPushButton[kind="danger"]:hover{background:#f85149}
QLineEdit,QTextEdit,QPlainTextEdit,QComboBox{background:@panel2;border:1px solid @border;border-radius:8px;padding:6px 10px;selection-background-color:@accent}
QLineEdit:focus,QTextEdit:focus,QComboBox:focus{border:1px solid @accent}
QComboBox{padding-right:24px;min-height:20px}
QComboBox::drop-down{border:0;width:22px}
QComboBox QAbstractItemView{background:@panel2;border:1px solid @border;selection-background-color:@accentbg;outline:0}
QTableWidget{background:@panel;alternate-background-color:@panel2;border:1px solid @border;border-radius:10px;gridline-color:transparent;selection-background-color:@accentbg;selection-color:@text;outline:0}
QTableWidget::item{padding:2px 8px;border:0}
QHeaderView{background:@panel2}
QHeaderView::section{background:@panel2;color:@muted;padding:9px 8px;border:0;border-bottom:1px solid @border;font-weight:600}
QScrollBar:vertical{background:transparent;width:11px;margin:2px}
QScrollBar::handle:vertical{background:@border;border-radius:4px;min-height:30px}
QScrollBar:horizontal{background:transparent;height:11px;margin:2px}
QScrollBar::handle:horizontal{background:@border;border-radius:4px;min-width:30px}
QScrollBar::add-line,QScrollBar::sub-line{width:0;height:0}
QSplitter::handle{background:transparent;height:8px}
QDialog{background:@bg}
QToolTip{background:@panel2;color:@text;border:1px solid @border}
'''
for _k, _v in sorted(PALETTE.items(), key=lambda kv: -len(kv[0])):  # longest token first (@panel2 before @panel)
    QSS = QSS.replace(_k, _v)

VALUE_COLORS = {
    'Critical': '#f85149', 'High': '#f0883e', 'Medium': '#d29922', 'Low': '#58a6ff', 'Info': '#8b949e',
    'Audit Failure': '#f85149', 'Audit Success': '#3fb950', 'Error': '#f85149', 'Warning': '#d29922', 'Information': '#58a6ff',
    'Open': '#f0883e', 'Investigating': '#58a6ff', 'Contained': '#d29922', 'Resolved': '#3fb950', 'Closed': '#8b949e',
    'Pending Approval': '#d29922', 'Approved (Manual)': '#3fb950', 'Rejected': '#8b949e', 'Approved': '#58a6ff',
    'Executed': '#3fb950', 'Failed': '#f85149', 'Refused': '#f0883e', 'Simulated': '#bc8cff', 'Dry-run': '#58a6ff',
    'Undone': '#8b949e', 'Expired': '#8b949e', 'Running': '#d29922', 'auto': '#f0883e', 'manual': '#8b949e',
    'DEMO': '#bc8cff', 'Live': '#3fb950', 'Collected': '#3fb950', 'Not collected': '#6e7681',
    'OK': '#3fb950', 'Listening': '#58a6ff', 'Not started': '#6e7681', 'Missing': '#f85149', 'Unknown': '#8b949e', 'Learning': '#d29922', 'Active': '#3fb950',
}


# ----------------------------------------------------------------------------- widgets
def button(text, handler=None, kind=None):
    b = QPushButton(text)
    if kind:
        b.setProperty('kind', kind)
    if handler:
        b.clicked.connect(handler)
    b.setCursor(Qt.PointingHandCursor)
    return b


class Card(QFrame):
    def __init__(self, label, color):
        super().__init__()
        self.setObjectName('Card')
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 14, 18, 14)
        v.setSpacing(0)
        self.value = QLabel('0')
        self.value.setStyleSheet('font-size:30px;font-weight:700;color:%s' % color)
        cap = QLabel(label)
        cap.setObjectName('CardLabel')
        v.addWidget(self.value)
        v.addWidget(cap)

    def set(self, n):
        self.value.setText('{:,}'.format(n))


class CollectorWorker(QThread):
    """Reads every Windows channel and writes to SQLite OFF the UI thread, so the window never freezes."""
    done = Signal(int, int, object, object, object)   # (new events, new alerts, cursors, channel status, auto actions)
    failed = Signal(str)

    def __init__(self, cursors, backfill_hours):
        super().__init__()
        self.cursors, self.backfill_hours = dict(cursors), backfill_hours

    def run(self):
        try:
            from windows_collector import read_new
            new, cursors, status = read_new(self.cursors, backfill_hours=self.backfill_hours)
            sink = []
            alerts = db.ingest_many(new, sink)
            db.save_cursors(cursors)            # only after the events are safely stored
            actions = response.auto_respond(sink)   # Critical ransomware / credential-theft alerts: act now
            self.done.emit(len(new), alerts, cursors, status, actions)
        except Exception as e:
            self.failed.emit(str(e))


class TaskWorker(QThread):
    """Run one function off the UI thread (response actions can take a few seconds)."""
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, *args):
        super().__init__()
        self.fn, self.args = fn, args

    def run(self):
        try:
            self.done.emit(self.fn(*self.args))
        except Exception as e:
            self.failed.emit(str(e))


class RespondDialog(QDialog):
    """Pick which suggested actions to queue for approval."""

    def __init__(self, plans, title, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(760, 420)
        self.plans = plans
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 16, 18, 14)
        info = QLabel('Suggested actions for this evidence. Ticked actions go to the Response page and run only after you approve them.\n'
                      'Greyed-out actions were refused by a safety check (reason shown).')
        info.setWordWrap(True)
        info.setObjectName('Muted')
        v.addWidget(info)
        self.list = QListWidget()
        for p in plans:
            it = QListWidgetItem('%s  \u2192  %s\n      %s' % (p['label'], p['target'], p['preview']))
            if p['blocked']:
                it.setFlags(it.flags() & ~Qt.ItemIsEnabled & ~Qt.ItemIsUserCheckable)
            else:
                it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
                it.setCheckState(Qt.Unchecked)
            self.list.addItem(it)
        if not plans:
            self.list.addItem('No automatic action fits this evidence. Use "Record manual action" to log what you did.')
        v.addWidget(self.list, 1)
        self.reason = QLineEdit()
        self.reason.setPlaceholderText('Reason / note (optional)')
        v.addWidget(self.reason)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.manual = buttons.addButton('Record manual action\u2026', QDialogButtonBox.ActionRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        v.addWidget(buttons)

    def chosen(self):
        return [self.plans[i] for i in range(min(self.list.count(), len(self.plans)))
                if self.list.item(i).flags() & Qt.ItemIsUserCheckable and self.list.item(i).checkState() == Qt.Checked]


class HealthWorker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def run(self):
        try:
            from windows_collector import health
            self.done.emit(health())
        except Exception as e:
            self.failed.emit(str(e))


class DataTable(QTableWidget):
    """Read-only table that keeps selection + scroll position across auto-refresh."""

    def __init__(self, headers, key_col=0, color_cols=()):
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.key_col, self.color_cols = key_col, set(color_cols)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(34)
        h = self.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.Interactive)
        h.setSectionResizeMode(len(headers) - 1, QHeaderView.Stretch)
        h.setMinimumSectionSize(70)
        h.setResizeContentsPrecision(60)  # measure only ~60 rows when auto-sizing columns (big speed-up)
        self.bold = QFont(self.font())
        self.bold.setBold(True)
        h.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        h.setHighlightSections(False)

    def selected_key(self):
        if self.key_col is None:
            return None
        row = self.currentRow()
        item = self.item(row, self.key_col) if row >= 0 else None
        return item.text() if item else None

    def load(self, data):
        key, bar = self.selected_key(), self.verticalScrollBar()
        pos = bar.value()
        self.setUpdatesEnabled(False)
        self.blockSignals(True)
        self.setRowCount(len(data))
        keep = -1
        for i, row in enumerate(data):
            for j, val in enumerate(row):
                text = '' if val is None else str(val)
                item = QTableWidgetItem(text)
                color = VALUE_COLORS.get(text) if j in self.color_cols else None
                if color:
                    item.setForeground(QBrush(QColor(color)))
                    item.setFont(self.bold)
                self.setItem(i, j, item)
            if key is not None and str(row[self.key_col]) == key:
                keep = i
        if keep >= 0:
            self.selectRow(keep)
        else:
            self.clearSelection()
            self.setCurrentCell(-1, -1)
        self.blockSignals(False)
        self.resizeColumnsToContents()  # ONE measuring pass (was one per cell = very slow)
        self.horizontalHeader().setSectionResizeMode(self.columnCount() - 1, QHeaderView.Stretch)
        self.setUpdatesEnabled(True)
        bar.setValue(pos)


class Dialog(QDialog):
    def __init__(self, title, fields, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        self.inputs = {}
        layout = QFormLayout(self)
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setVerticalSpacing(12)
        for label, kind, opts in fields:
            w = QComboBox() if kind == 'combo' else QTextEdit() if kind == 'memo' else QLineEdit()
            if kind == 'combo':
                w.addItems(opts)
            if kind == 'memo':
                w.setMinimumHeight(90)
            self.inputs[label] = w
            layout.addRow(label, w)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def value(self, label):
        w = self.inputs[label]
        return w.currentText() if isinstance(w, QComboBox) else w.toPlainText() if isinstance(w, QTextEdit) else w.text()


def page(*children, spacing=12):
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(22, 18, 22, 18)
    v.setSpacing(spacing)
    for c in children:
        if isinstance(c, (QHBoxLayout, QVBoxLayout)):
            v.addLayout(c)
        else:
            v.addWidget(c)
    return w


def row(*widgets, stretch_at=None):
    h = QHBoxLayout()
    h.setSpacing(10)
    for i, w in enumerate(widgets):
        if w is None:
            h.addStretch(1)
        else:
            h.addWidget(w, 1 if i == stretch_at else 0)
    return h


# ----------------------------------------------------------------------------- main window
def short(text, n=160):
    text = (text or '').replace('\r', ' ').replace('\n', ' ')
    return text if len(text) <= n else text[:n] + '…'


def detail_of(r):
    """Most useful single 'what happened' text for an event row."""
    return r['command_line'] or r['target'] or r['status'] or r['logon_type'] or ''


SILENT_MINUTES = 20      # Sysmon normally logs something every few minutes


class Main(QMainWindow):
    PAGES = ['Overview', 'Events', 'Alerts', 'Incidents', 'Response', 'Activity', 'Coverage', 'Tuning']

    def __init__(self):
        super().__init__()
        db.init()
        self.setWindowTitle('MiniSOC 2.4 | Local Security Monitor')
        self.resize(1440, 880)
        self.collecting = False
        self.cursors = db.cursors()
        self.channel_status = {}
        self.started_at = None
        self.event_rows = {}
        self.worker = None
        self.health_worker = None
        self.tasks = []
        self.debounce = QTimer(self)
        self.debounce.setSingleShot(True)
        self.debounce.setInterval(350)
        self.debounce.timeout.connect(self.refresh)
        self._build()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(4000)
        self.prune_timer = QTimer(self)
        self.prune_timer.timeout.connect(self.prune)
        self.prune_timer.start(6 * 3600 * 1000)
        self.expiry_timer = QTimer(self)
        self.expiry_timer.timeout.connect(lambda: self.run_task(response.expire_blocks, self._expired))
        self.expiry_timer.start(60 * 1000)
        self.tray = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(self.style().standardIcon(QStyle.SP_MessageBoxWarning), self)
            self.tray.setToolTip('MiniSOC')
            self.tray.show()
        self.set_status('Collector stopped', 'idle')
        QTimer.singleShot(1500, self.prune)
        self.refresh()

    # ---------------------------------------------------------------- layout
    def _build(self):
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.setCentralWidget(central)

        side = QFrame()
        side.setObjectName('Sidebar')
        side.setFixedWidth(220)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(0, 0, 0, 0)
        sv.setSpacing(0)
        brand = QLabel('MiniSOC')
        brand.setObjectName('Brand')
        sub = QLabel('Local security monitor  •  v2.4')
        sub.setObjectName('BrandSub')
        self.nav = QListWidget()
        self.nav.setObjectName('Nav')
        self.nav.addItems(self.PAGES)
        foot = QLabel('Security • System • Sysmon\nPowerShell • Defender\nTasks • RDP\nRun as Administrator')
        foot.setObjectName('SideFoot')
        for w in (brand, sub):
            sv.addWidget(w)
        sv.addWidget(self.nav, 1)
        sv.addWidget(foot)
        root.addWidget(side)

        right = QVBoxLayout()
        right.setSpacing(0)
        header = QFrame()
        header.setObjectName('Header')
        header.setFixedHeight(64)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(22, 0, 22, 0)
        hl.setSpacing(10)
        self.title = QLabel('Overview')
        self.title.setObjectName('PageTitle')
        self.order_box = QComboBox()
        self.order_box.addItem('Newest first  (new → old)', 'DESC')
        self.order_box.addItem('Oldest first  (old → new)', 'ASC')
        self.order_box.setToolTip('Sort every list by time')
        self.tz_box = QComboBox()
        self.tz_box.addItem('UTC', False)
        self.tz_box.addItem('Local time', True)
        self.tz_box.setCurrentIndex(1)
        self.tz_box.setToolTip('Time zone used to display times')
        self.pill = QLabel()
        self.pill.setFixedHeight(28)
        sort_lbl, tz_lbl = QLabel('Sort'), QLabel('Time')
        sort_lbl.setObjectName('Muted')
        tz_lbl.setObjectName('Muted')
        hl.addWidget(self.title)
        hl.addStretch(1)
        for w in (sort_lbl, self.order_box, tz_lbl, self.tz_box, self.pill):
            hl.addWidget(w)
        right.addWidget(header)

        self.stack = QStackedWidget()
        right.addWidget(self.stack, 1)
        root.addLayout(right, 1)

        for builder in (self._overview, self._events, self._alerts, self._incidents, self._responses,
                        self._activity, self._coverage, self._tuning):
            self.stack.addWidget(builder())
        self.nav.currentRowChanged.connect(self._goto)
        self.nav.setCurrentRow(0)
        for c in (self.order_box, self.tz_box):
            c.currentIndexChanged.connect(self.refresh)

    def _goto(self, i):
        self.stack.setCurrentIndex(i)
        self.title.setText(self.PAGES[i])
        self.refresh()

    def _overview(self):
        self.k_events = Card('Events recorded', '#e6edf3')
        self.k_alerts = Card('Open alerts', '#f0883e')
        self.k_crit = Card('Critical / High open', '#f85149')
        self.k_inc = Card('Open incidents', '#58a6ff')
        self.k_pend = Card('Pending responses', '#d29922')
        cards = QHBoxLayout()
        cards.setSpacing(12)
        for c in (self.k_events, self.k_alerts, self.k_crit, self.k_inc, self.k_pend):
            cards.addWidget(c, 1)
        self.iso_banner = QFrame()
        self.iso_banner.setObjectName('IsoBanner')
        self.iso_banner.setStyleSheet('#IsoBanner{background:#3d1416;border:1px solid #f85149;border-radius:10px}')
        bl = QHBoxLayout(self.iso_banner)
        bl.setContentsMargins(16, 10, 16, 10)
        self.iso_lbl = QLabel('')
        self.iso_lbl.setStyleSheet('color:#ffdcd7;font-weight:600')
        self.iso_lbl.setWordWrap(True)
        bl.addWidget(self.iso_lbl, 1)
        bl.addWidget(button('Release isolation', self.release_isolation, 'danger'))
        self.iso_banner.hide()
        self.btn_start = button('▶  Start Collector', self.start)
        self.btn_stop = button('■  Stop Collector', self.stop, 'ghost')
        self.btn_stop.setEnabled(False)
        self.collect_status = QLabel('')
        self.collect_status.setObjectName('Muted')
        controls = row(self.btn_start, self.btn_stop, button('Add Demo Attack', self.demo, 'ghost'),
                       button('Refresh', self.refresh, 'ghost'), None, self.collect_status)
        self.channels_lbl = QLabel('Channels: not started')
        self.channels_lbl.setObjectName('Muted')
        self.channels_lbl.setWordWrap(True)
        sec = QLabel('Recent alerts')
        sec.setObjectName('Section')
        self.recent = DataTable(['Last seen', 'Severity', 'Rule', 'ATT&CK', 'Hits', 'Summary'], key_col=None, color_cols=[1])
        return page(self.iso_banner, cards, controls, self.channels_lbl, sec, self.recent, spacing=14)

    def _events(self):
        self.search = QLineEdit()
        self.search.setPlaceholderText('Search event ID, user, IP, process, command line, file, registry key, hash…')
        self.search.setClearButtonEnabled(True)
        self.channel_box = QComboBox()
        self.channel_box.addItem('All channels', '')
        for ch in cat.CATALOG:
            self.channel_box.addItem(ch, ch)
        self.level_box = QComboBox()
        self.level_box.addItem('All levels', '')
        for lv in cat.LEVELS:
            self.level_box.addItem(lv, lv)
        self.source_box = QComboBox()
        for s in ('All sources', 'Live', 'Demo'):
            self.source_box.addItem(s, '' if s.startswith('All') else s)
        self.limit_box = QComboBox()
        for n in (500, 1000, 5000, 20000):
            self.limit_box.addItem('Latest {:,}'.format(n), n)
        self.limit_box.setCurrentIndex(1)
        self.count_lbl = QLabel('')
        self.count_lbl.setObjectName('Muted')
        self.eventtab = DataTable(['Time', 'Row', 'Channel', 'Event ID', 'Event', 'Level', 'User', 'Process', 'Source IP', 'Detail', 'Source'],
                                  key_col=1, color_cols=[5, 10])
        self.eventtab.itemSelectionChanged.connect(self.show_event)
        self.detail = QPlainTextEdit()
        self.detail.setObjectName('Detail')
        self.detail.setReadOnly(True)
        self.detail.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.detail.setPlaceholderText('Select an event to see every field MiniSOC recorded, including all named EventData fields.')
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.eventtab)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        p = page(row(self.search, self.channel_box, self.level_box, self.source_box, self.limit_box, stretch_at=0), self.count_lbl, split)
        self.search.textChanged.connect(lambda *_: self.debounce.start())
        for c in (self.channel_box, self.level_box, self.source_box, self.limit_box):
            c.currentIndexChanged.connect(self.refresh)
        return p

    def _alerts(self):
        self.alerttab = DataTable(['ID', 'Last seen', 'Rule', 'Severity', 'ATT&CK', 'Hits', 'Summary', 'User', 'Incident', 'Status'],
                                  color_cols=[3, 9])
        return page(self.alerttab, row(button('Mark Selected Closed', self.close_alert),
                                       button('Respond\u2026', self.respond_alert, 'ghost'),
                                       button('Allowlist (stop alerting on this)…', self.allow_from_alert, 'ghost'), None))

    def _incidents(self):
        self.incidenttab = DataTable(['ID', 'Title', 'Severity', 'Status', 'Alerts', 'ATT&CK', 'Owner', 'Created', 'Last activity'],
                                     color_cols=[2, 3])
        self.incidenttab.itemSelectionChanged.connect(self.show_incident)
        self.inc_detail = QPlainTextEdit()
        self.inc_detail.setObjectName('Detail')
        self.inc_detail.setReadOnly(True)
        self.inc_detail.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.inc_detail.setPlaceholderText('Select an incident to see its timeline: every correlated alert in order, with the evidence.')
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.incidenttab)
        split.addWidget(self.inc_detail)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        return page(split, row(button('Create Incident', self.new_incident),
                               button('Update Selected', self.edit_incident, 'ghost'),
                               button('Respond\u2026', self.request, 'ghost'), None))

    def _responses(self):
        self.resp_note = QLabel('')
        self.resp_note.setObjectName('Muted')
        self.resp_note.setWordWrap(True)
        self.rtab = DataTable(['ID', 'Mode', 'Action', 'Target', 'Status', 'Incident', 'Requested', 'Executed', 'Result'], color_cols=[1, 4])
        self.rtab.itemSelectionChanged.connect(self.show_response)
        self.resp_detail = QPlainTextEdit()
        self.resp_detail.setObjectName('Detail')
        self.resp_detail.setReadOnly(True)
        self.resp_detail.setPlaceholderText('Select a response to see exactly what was (or will be) run and its result.')
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.rtab)
        split.addWidget(self.resp_detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        self.btn_approve = button('Approve && run', lambda: self.review(True))
        return page(self.resp_note, split, row(self.btn_approve, button('Reject', lambda: self.review(False), 'danger'),
                                               button('Undo selected', self.undo_response, 'ghost'), None))

    def _activity(self):
        self.activitytab = DataTable(['Time', 'Actor', 'Action', 'Details'], key_col=None)
        return page(self.activitytab)

    def _coverage(self):
        self.cov_summary = QLabel('')
        self.cov_summary.setWordWrap(True)
        self.cov_levels = QLabel('')
        self.cov_levels.setObjectName('Muted')
        self.cov_levels.setWordWrap(True)
        self.covtab = DataTable(['Channel', 'Event ID', 'Event', 'Category', 'Status', 'Recorded', 'Last seen', 'Used by rules / note'],
                                key_col=None, color_cols=[4])
        sec = QLabel('Health check  —  is Windows actually writing the logs MiniSOC needs?')
        sec.setObjectName('Section')
        self.health_lbl = QLabel('Press "Run health check" (works best when MiniSOC runs as Administrator).')
        self.health_lbl.setObjectName('Muted')
        self.btn_health = button('Run health check', self.run_health, 'ghost')
        self.healthtab = DataTable(['Area', 'Check', 'State', 'Detail', 'How to fix'], key_col=None, color_cols=[2])
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.covtab)
        hw = QWidget()
        hv = QVBoxLayout(hw)
        hv.setContentsMargins(0, 6, 0, 0)
        hv.addLayout(row(sec, None, self.health_lbl, self.btn_health))
        hv.addWidget(self.healthtab)
        split.addWidget(hw)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        return page(self.cov_summary, self.cov_levels, split)

    def _tuning(self):
        sec1 = QLabel('Baseline (anomaly detection)')
        sec1.setObjectName('Section')
        self.base_lbl = QLabel('')
        self.base_lbl.setWordWrap(True)
        self.days_box = QComboBox()
        for d in (1, 3, 7, 14, 30):
            self.days_box.addItem('Learn for %d day%s' % (d, 's' if d > 1 else ''), d)
        self.days_box.setCurrentIndex(self.days_box.findData(int(float(db.setting('baseline_days', 7)))))
        self.days_box.currentIndexChanged.connect(lambda *_: (db.set_setting('baseline_days', self.days_box.currentData()), self.refresh()))
        sec2 = QLabel('Collection')
        sec2.setObjectName('Section')
        self.backfill_box = QComboBox()
        for label, h in (('First start: new events only', 0), ('First start: backfill last 24 hours', 24),
                         ('First start: backfill last 7 days', 168)):
            self.backfill_box.addItem(label, h)
        self.backfill_box.setCurrentIndex(max(0, self.backfill_box.findData(int(db.setting('backfill_hours', 24)))))
        self.backfill_box.currentIndexChanged.connect(lambda *_: db.set_setting('backfill_hours', self.backfill_box.currentData()))
        self.backfill_box.setToolTip('Applies to channels MiniSOC has never read before (e.g. right after installing Sysmon).')
        self.retention_box = QComboBox()
        for label, d in (('Keep events 7 days', 7), ('Keep events 30 days', 30), ('Keep events 90 days', 90),
                         ('Keep events 1 year', 365), ('Keep events forever', 0)):
            self.retention_box.addItem(label, d)
        self.retention_box.setCurrentIndex(max(0, self.retention_box.findData(int(db.setting('retention_days', 30)))))
        self.retention_box.currentIndexChanged.connect(lambda *_: db.set_setting('retention_days', self.retention_box.currentData()))
        note = QLabel('Events linked to an alert are never deleted.')
        note.setObjectName('Muted')
        sec_r = QLabel('Response')
        sec_r.setObjectName('Section')
        self.auto_box = QComboBox()
        for label, v in (('Auto-response: ON for Critical ransomware / credential-theft alerts', 'on'),
                         ('Auto-response: DRY-RUN (log what would happen)', 'dry-run'), ('Auto-response: OFF (everything manual)', 'off')):
            self.auto_box.addItem(label, v)
        self.auto_box.setCurrentIndex(max(0, self.auto_box.findData(response.settings()[0])))
        self.auto_box.currentIndexChanged.connect(lambda *_: (db.set_setting('auto_response', self.auto_box.currentData()), self.refresh()))
        self.ttl_box = QComboBox()
        for label, h in (('IP blocks expire after 1 hour', 1), ('IP blocks expire after 24 hours', 24), ('IP blocks expire after 7 days', 168),
                         ('IP blocks never expire', 0)):
            self.ttl_box.addItem(label, h)
        self.ttl_box.setCurrentIndex(max(0, self.ttl_box.findData(int(db.setting('block_ttl_hours', 24)))))
        self.ttl_box.currentIndexChanged.connect(lambda *_: db.set_setting('block_ttl_hours', self.ttl_box.currentData()))
        policy = QLabel('Automatic: ' + ';  '.join('%s \u2192 %s' % (r, ' + '.join(a.replace('_', ' ') for a in acts))
                                                  for r, acts in response.AUTO_POLICY.items()) + '.  Only when the alert is Critical.')
        policy.setObjectName('Muted')
        policy.setWordWrap(True)
        sec3 = QLabel('Allowlist  —  suppress known-good activity (case-insensitive "contains" match)')
        sec3.setObjectName('Section')
        self.allowtab = DataTable(['ID', 'Rule', 'Field', 'Contains', 'Note', 'Added'])
        return page(sec1, self.base_lbl,
                    row(self.days_box, button('Reset baseline', self.reset_baseline, 'ghost'), None),
                    sec2, row(self.backfill_box, self.retention_box, button('Prune now', lambda: self.prune(True), 'ghost'), note, None),
                    sec_r, row(self.auto_box, self.ttl_box, None), policy,
                    sec3, self.allowtab,
                    row(button('Add entry…', self.add_allow), button('Remove selected', self.remove_allow, 'danger'), None))

    # ---------------------------------------------------------------- helpers
    def order(self):
        return self.order_box.currentData()

    def local(self):
        return bool(self.tz_box.currentData())

    def t(self, value):
        return cat.format_time(value, self.local())

    def set_status(self, text, state):
        color = {'ok': '#3fb950', 'idle': '#8b949e', 'error': '#f85149'}[state]
        self.pill.setText('●  ' + text.split(' • ')[0])
        self.pill.setStyleSheet('color:%s;background:#0d1117;border:1px solid %s;border-radius:11px;padding:4px 12px;font-weight:600'
                                % (color, color))
        self.collect_status.setText(text)

    # ---------------------------------------------------------------- refresh
    def refresh(self, *_):
        """Update the stat cards (cheap) and ONLY the page the user is looking at."""
        if not hasattr(self, 'allowtab'):
            return
        order, s = self.order(), db.stats()
        self.k_events.set(s['events'])
        self.k_alerts.set(s['open_alerts'])
        self.k_crit.set(s['crit_high'])
        self.k_inc.set(s['open_incidents'])
        self.k_pend.set(s['pending'])
        iso = db.isolation_active()
        self.iso_banner.setVisible(bool(iso))
        if iso:
            self.iso_lbl.setText('\u26a0  This computer is ISOLATED from the network (response #%s). Investigate first, then release.' % iso)
        name = self.PAGES[self.stack.currentIndex()]
        if name == 'Overview':
            self.recent.load([[self.t(r['last_seen_utc']), r['severity'], r['rule_id'], r['mitre'], r['hit_count'], r['summary']]
                              for r in db.alerts('DESC', 14)])
        elif name == 'Events':
            ev, total = db.events(self.search.text(), order, self.level_box.currentData(), self.source_box.currentData(),
                                  self.limit_box.currentData(), self.channel_box.currentData())
            self.event_rows = {r['id']: r for r in ev}
            self.eventtab.load([[self.t(r['time_utc']), r['id'], r['channel'], r['event_id'], cat.event_name(r['event_id'], r['channel']),
                                 r['level'], r['username'], (r['process'] or '').split('\\')[-1], r['source_ip'] or r['dest_ip'],
                                 short(detail_of(r)), 'DEMO' if r['is_demo'] else 'Live'] for r in ev])
            self.count_lbl.setText('Showing {:,} of {:,} matching events • {}'.format(
                len(ev), total, 'newest first' if order == 'DESC' else 'oldest first'))
            self.show_event()
        elif name == 'Alerts':
            self.alerttab.load([[r['id'], self.t(r['last_seen_utc']), r['rule_id'], r['severity'], r['mitre'], r['hit_count'], r['summary'],
                                 r['username'], ('#%s' % r['incident_id']) if r['incident_id'] else '', r['status']] for r in db.alerts(order)])
        elif name == 'Incidents':
            self.incidenttab.load([[r['id'], r['title'], r['severity'], r['status'], r['alert_count'], r['mitre'], r['owner'],
                                    self.t(r['created_utc']), self.t(r['last_event_utc'])] for r in db.incidents(order)])
            self.show_incident()
        elif name == 'Response':
            self.resp_rows = {r['id']: r for r in db.response_requests(order)}
            self.rtab.load([[r['id'], r['mode'] or 'manual', r['action'], r['target'] or '', r['status'],
                             ('#%s' % r['incident_id']) if r['incident_id'] else '', self.t(r['created_utc']), self.t(r['executed_utc']),
                             short((r['result'] or '').split('\n')[-1], 120)] for r in self.resp_rows.values()])
            mode = response.settings()[0]
            self.resp_note.setText({'on': 'Auto-response is ON: Critical ransomware and credential-theft alerts are answered immediately '
                                          '(kill the process, isolate the computer). Everything else waits for your approval here.',
                                    'dry-run': 'Auto-response is in DRY-RUN: automatic actions are only logged, nothing is executed.',
                                    'off': 'Auto-response is OFF: every action waits for your approval.'}.get(mode, '')
                                   + '  Actions need MiniSOC to run as Administrator.')
            self.show_response()
        elif name == 'Activity':
            self.activitytab.load([[self.t(r['created_utc']), r['actor'], r['action'], r['details']] for r in db.activities(order)])
        elif name == 'Coverage':
            self.refresh_coverage()
        elif name == 'Tuning':
            self.refresh_tuning()

    def refresh_coverage(self):
        per_id, levels, span, demo = db.coverage()
        rules = {}
        for rule, evs in RULE_EVENTS.items():
            for ev in evs:
                rules.setdefault(tuple(ev), []).append(rule)
        data = []
        for ch, evs in cat.CATALOG.items():
            st = self.channel_status.get(ch)
            for eid, (name, category) in evs.items():
                r = per_id.get((ch, eid))
                state = 'Collected' if r else 'Listening' if st == 'ok' else 'Missing' if st else 'Not started'
                data.append([ch, eid, name, category, state, r['n'] if r else 0, self.t(r['last']) if r else '–',
                             ', '.join(rules.get((ch, eid), [])) or '(recorded for investigation)'])
        for (ch, eid), (name, category, note) in cat.GAPS.items():
            data.append([ch, eid, name, category, 'Not collected', 0, '–', note])
        self.covtab.load(data)
        total_ids = sum(len(v) for v in cat.CATALOG.values())
        chans = ', '.join('%s: %s' % (k, v) for k, v in self.channel_status.items()) or 'collector not started yet'
        if span['n']:
            self.cov_summary.setText('{} of {} event types seen • {:,} live events • {} to {}\nChannels → {}'.format(
                len(per_id), total_ids, span['n'], self.t(span['first']), self.t(span['last']), chans))
        else:
            self.cov_summary.setText('No live events recorded yet. Start the collector (demo events are not counted here).\nChannels → ' + chans)
        lv = '  •  '.join('{}: {:,}'.format(k, v) for k, v in sorted(levels.items())) or 'none yet'
        self.cov_levels.setText('Levels recorded (live): %s   |   Demo events in database: %d   |   %d detection rules loaded'
                                % (lv, demo, len(RULE_EVENTS)))

    def refresh_tuning(self):
        start, until, counts = db.baseline_status()
        learned = ', '.join('%s: %d' % (k.replace('_', ' '), v) for k, v in sorted(counts.items())) or 'nothing yet'
        if not start:
            self.base_lbl.setText('Not started. Learning begins with the first live process / RDP / network event.')
        elif until and until > cat.to_dt(None):
            self.base_lbl.setText('Learning — recording what is normal on this machine until %s. No anomaly alerts until then.\n'
                                  'Learned so far: %s' % (self.t(until.isoformat()), learned))
        else:
            self.base_lbl.setText('Active — learning finished %s. Never-seen process chains, RDP sources and internet-using '
                                  'processes now raise alerts.\nKnown items: %s' % (self.t(until.isoformat()), learned))
        self.allowtab.load([[r['id'], r['rule_id'], r['field'], r['pattern'], r['note'], self.t(r['created_utc'])] for r in db.allowlist()])

    def show_event(self):
        key = self.eventtab.selected_key()
        r = self.event_rows.get(int(key)) if key and key.isdigit() else None
        if not r:
            self.detail.setPlainText('')
            return
        lines = ['%s %s  •  %s' % (r['channel'], r['event_id'], cat.event_name(r['event_id'], r['channel'])),
                 'Category      : %s' % cat.event_category(r['event_id'], r['channel']),
                 'Level         : %s' % r['level'],
                 'Time UTC      : %s     local: %s' % (cat.format_time(r['time_utc']), cat.format_time(r['time_utc'], True)),
                 'Computer      : %s' % r['computer'],
                 'Origin        : %s   Record ID: %s   Row: %s' % ('DEMO' if r['is_demo'] else 'Live', r['record_id'], r['id'])]
        labels = [('username', 'Account'), ('subject_user', 'Done by'), ('source_ip', 'Source IP'), ('logon_type', 'Logon type'),
                  ('logon_id', 'Logon ID'), ('process', 'Process'), ('parent_process', 'Parent'), ('command_line', 'Command'),
                  ('target', 'Target'), ('dest_ip', 'Destination'), ('status', 'Status / access'), ('hash', 'Hashes'),
                  ('process_guid', 'Process GUID'), ('parent_guid', 'Parent GUID'), ('tags', 'Tags')]
        for k, label in labels:
            if r[k]:
                val = r[k] + ((':' + r['dest_port']) if k == 'dest_ip' and r['dest_port'] else '')
                lines.append('%-14s: %s' % (label, val))
        try:
            data = json.loads(r['data_json'] or '{}')
        except ValueError:
            data = {}
        if data:
            lines += ['', 'All event fields:'] + ['  %-28s %s' % (k, v) for k, v in data.items()]
        elif r['raw']:
            lines += ['', 'Raw insert strings (v2.2 record):'] + ['  [%02d] %s' % (i, v) for i, v in enumerate(r['raw'].split(' | '))]
        self.detail.setPlainText('\n'.join(lines))

    def show_incident(self):
        key = self.incidenttab.selected_key()
        inc = db.incident(int(key)) if key and key.isdigit() else None
        if not inc:
            self.inc_detail.setPlainText('')
            return
        keys = [k for k in (inc['corr_keys'] or '').strip('|').split('|') if k]
        lines = ['Incident #%s  •  %s  •  %s' % (inc['id'], inc['severity'], inc['status']), inc['title'],
                 'ATT&CK      : %s' % (inc['mitre'] or '–'),
                 'Linked by   : %s' % (', '.join(keys) or 'manual incident'), '', 'Timeline:']
        for a in db.incident_alerts(inc['id']):
            lines.append('  %s  %-8s %-28s %s%s' % (self.t(a['event_time_utc']), a['severity'], a['rule_id'], short(a['summary'], 200),
                                                    ('  (x%d)' % a['hit_count']) if a['hit_count'] > 1 else ''))
            if a['command_line'] and a['command_line'] not in a['summary']:
                lines.append('  %s  ↳ %s' % (' ' * 19, short(a['command_line'], 220)))
        if not keys and inc['description']:
            lines += ['', inc['description']]
        self.inc_detail.setPlainText('\n'.join(lines))

    # ---------------------------------------------------------------- collector
    def start(self):
        if platform.system() != 'Windows':
            QMessageBox.warning(self, 'Windows required', 'Live collection requires Windows 10/11. You can use "Add Demo Attack" on this computer.')
            return
        self.collecting = True
        self.started_at = cat.to_dt(None)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.set_status('Collector running • reading channels…', 'ok')
        self.poll()

    def stop(self):
        self.collecting = False
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.set_status('Collector stopped', 'idle')

    def poll(self):
        if not self.collecting or (self.worker and self.worker.isRunning()):
            return
        self.worker = CollectorWorker(self.cursors, int(db.setting('backfill_hours', 24)))
        self.worker.done.connect(self._poll_done)
        self.worker.failed.connect(self._poll_failed)
        self.worker.start()

    def _poll_done(self, count, alerts, cursors, status, actions=()):
        self.cursors = cursors
        if actions:
            text = '\n'.join('%s  (%s)' % (desc, st) for _, st, desc in actions)
            self.notify('MiniSOC auto-response', text)
        self._watch_sensors(status)
        self.channel_status = status
        ok = [k for k, v in status.items() if v == 'ok']
        bad = ['%s (%s)' % (k, v) for k, v in status.items() if v != 'ok']
        self.channels_lbl.setText('Channels live: %s%s' % (', '.join(ok) or 'none', ('     Not available: ' + ', '.join(bad)) if bad else ''))
        if self.collecting:
            self.set_status('Collector active • %d/%d channels • %d new events • %d new alerts' % (len(ok), len(status), count, alerts), 'ok')
            fast = count >= 1000 or response.settings()[0] != 'off'
            QTimer.singleShot(2500 if fast else 5000, self.poll)     # ransomware does not wait
        if count or alerts:
            self.refresh()

    def _watch_sensors(self, status):
        """The attacker's favourite move is to blind the sensor. Alert when a channel disappears or Sysmon goes quiet."""
        for ch, st in status.items():
            if self.channel_status.get(ch) == 'ok' and st != 'ok':
                db.system_alert('SENSOR_CHANNEL_LOST', 'High', 'T1562.002', 'Channel %s stopped being readable: %s' % (ch, st), ch)
        if status.get('Sysmon') == 'ok' and self.started_at and (cat.to_dt(None) - self.started_at).total_seconds() > SILENT_MINUTES * 60:
            last = db.last_event_time('Sysmon')
            if last and (cat.to_dt(None) - cat.to_dt(last)).total_seconds() > SILENT_MINUTES * 60:
                db.system_alert('SENSOR_SILENT', 'Medium', 'T1562.001',
                                'No Sysmon events for %d+ minutes - Sysmon may be stopped, filtered or tampered with' % SILENT_MINUTES, 'Sysmon')

    def _poll_failed(self, msg):
        self.collecting = False
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.set_status('Collector error: %s' % msg, 'error')

    def run_health(self):
        if platform.system() != 'Windows':
            self.health_lbl.setText('Health check needs Windows 10/11.')
            return
        if self.health_worker and self.health_worker.isRunning():
            return
        self.btn_health.setEnabled(False)
        self.health_lbl.setText('Checking channels, audit policy and registry…')
        self.health_worker = HealthWorker()
        self.health_worker.done.connect(self._health_done)
        self.health_worker.failed.connect(lambda m: (self.health_lbl.setText('Health check failed: ' + m), self.btn_health.setEnabled(True)))
        self.health_worker.start()

    def _health_done(self, rows):
        self.btn_health.setEnabled(True)
        self.healthtab.load([list(r) for r in rows])
        missing = sum(1 for r in rows if r[2] in ('Missing', 'Warning'))
        self.health_lbl.setText('All checks passed.' if not missing else
                                '%d item(s) need attention — run enable_auditing.bat / install_sysmon.bat as Administrator.' % missing)

    def demo(self):
        sink = []
        n = db.add_demo(sink)
        acts = response.auto_respond(sink)
        if acts:
            self.notify('MiniSOC auto-response (DEMO)', '\n'.join('%s  (%s)' % (d, st) for _, st, d in acts))
        self.refresh()
        QMessageBox.information(self, 'Demo attack', 'A synthetic attack chain was added (%d alerts): RDP brute force → logon → '
                                'discovery → encoded PowerShell → lsass access → service persistence → shadow-copy deletion.\n\n'
                                'Open Incidents to see how they were correlated into one incident, and Response to see the '
                                'automatic actions (SIMULATED for demo events - nothing is touched). Rows are labeled DEMO.' % n)

    def prune(self, manual=False):
        days = int(db.setting('retention_days', 30))
        if not days:
            if manual:
                QMessageBox.information(self, 'Retention', 'Retention is set to keep events forever.')
            return
        n = db.prune(days)
        if manual:
            QMessageBox.information(self, 'Retention', 'Deleted %d events older than %d days.' % (n, days))
            self.refresh()

    # ---------------------------------------------------------------- actions
    def selected(self, table, msg):
        key = table.selected_key()
        if key is None or not key.isdigit():
            QMessageBox.information(self, 'Select', msg)
            return None
        return int(key)

    def close_alert(self):
        aid = self.selected(self.alerttab, 'Select an alert first.')
        if aid is not None:
            db.close_alert(aid)
            self.refresh()

    def _allow_dialog(self, rule_id='*', field='process', value=''):
        rule_ids = ['*'] + sorted(RULE_EVENTS)
        d = Dialog('Allowlist entry', [('Rule', 'combo', rule_ids), ('Field', 'combo', list(ALLOW_FIELDS)),
                                       ('Contains', 'text', []), ('Note', 'text', [])], self)
        d.inputs['Rule'].setCurrentText(rule_id)
        d.inputs['Field'].setCurrentText(field)
        d.inputs['Contains'].setText(value)
        d.inputs['Contains'].setToolTip('Case-insensitive. The rule is suppressed when the field CONTAINS this text.')
        if d.exec():
            try:
                db.add_allow(d.value('Rule'), d.value('Field'), d.value('Contains'), d.value('Note'))
            except ValueError as e:
                QMessageBox.warning(self, 'Allowlist', str(e))
            self.refresh()

    def allow_from_alert(self):
        aid = self.selected(self.alerttab, 'Select an alert first.')
        if aid is None:
            return
        a = next((r for r in db.alerts('DESC', 5000) if r['id'] == aid), None)
        if not a:
            return
        field, value = next(((f, a[k]) for f, k in (('process', 'process'), ('target', 'ev_target'), ('username', 'username'),
                                                     ('source_ip', 'source_ip')) if a[k]), ('process', ''))
        self._allow_dialog(a['rule_id'], field, value)

    def add_allow(self):
        self._allow_dialog()

    def remove_allow(self):
        aid = self.selected(self.allowtab, 'Select an allowlist entry first.')
        if aid is not None:
            db.delete_allow(aid)
            self.refresh()

    def reset_baseline(self):
        if QMessageBox.question(self, 'Reset baseline', 'Forget everything learned and start a new learning period?') == QMessageBox.Yes:
            db.reset_baseline()
            self.refresh()

    def new_incident(self):
        d = Dialog('New incident', [('Title', 'text', []), ('Severity', 'combo', ['Info', 'Low', 'Medium', 'High', 'Critical']),
                                    ('Owner', 'text', []), ('Description', 'memo', [])], self)
        if d.exec():
            db.create_incident(d.value('Title') or 'Untitled incident', d.value('Severity'), d.value('Description'), d.value('Owner'))
            self.refresh()

    def edit_incident(self):
        iid = self.selected(self.incidenttab, 'Select an incident first.')
        if iid is None:
            return
        d = Dialog('Update incident', [('Status', 'combo', ['Open', 'Investigating', 'Contained', 'Resolved', 'Closed']), ('Owner', 'text', [])], self)
        if d.exec():
            db.update_incident(iid, d.value('Status'), d.value('Owner'))
            self.refresh()

    def _respond(self, plans, iid, title):
        d = RespondDialog(plans, title, self)
        d.manual.clicked.connect(lambda: (d.done(2)))
        result = d.exec()
        if result == 2:
            m = Dialog('Record manual action', [('Action', 'combo', ['Disable account (manual)', 'Terminate session (manual)', 'Kill process (manual)',
                                                                     'Block IP in firewall (manual)', 'Isolate host (manual)', 'Other manual action']),
                                                ('Reason', 'memo', [])], self)
            if m.exec():
                db.request_response(iid, m.value('Action'), m.value('Reason'))
        elif result:
            chosen = d.chosen()
            for p in chosen:
                db.add_response(iid, p, d.reason.text() or 'Requested from %s' % title)
            if chosen:
                self.nav.setCurrentRow(self.PAGES.index('Response'))
        self.refresh()

    def request(self):
        iid = self.selected(self.incidenttab, 'Select an incident first.')
        if iid is not None:
            self.run_task(response.suggest_for_incident, lambda plans: self._respond(plans, iid, 'Respond to incident #%s' % iid), iid)

    def respond_alert(self):
        aid = self.selected(self.alerttab, 'Select an alert first.')
        if aid is None:
            return
        a = db.alert(aid)
        self.run_task(response.suggest_for_alert, lambda plans: self._respond(plans, a['incident_id'], 'Respond to alert #%s %s' % (aid, a['rule_id'])), a)

    def review(self, approved):
        rid = self.selected(self.rtab, 'Select a request first.')
        if rid is None:
            return
        r = db.response_request(rid)
        if r['status'] != 'Pending Approval':
            QMessageBox.information(self, 'Response', 'Request #%s is already %s.' % (rid, r['status']))
            return
        if approved:
            plan = json.loads(r['plan_json'] or '{}')
            what = response.preview(plan) if plan else 'Record-only request (nothing is executed).'
            if QMessageBox.question(self, 'Run this action?', '%s\n\n%s\n\nThis changes this computer. Continue?'
                                    % (r['action'] + (' \u2192 ' + r['target'] if r['target'] else ''), what)) != QMessageBox.Yes:
                return
        db.review_response(rid, approved, 'Local Admin', '')
        if approved:
            self.run_task(response.run_request, lambda st: (self.notify('MiniSOC response', 'Request #%s: %s' % (rid, st)), self.refresh()), rid)
        self.refresh()

    def undo_response(self):
        rid = self.selected(self.rtab, 'Select an executed action first.')
        if rid is None:
            return
        r = db.response_request(rid)
        plan = json.loads(r['plan_json'] or '{}')
        if r['status'] != 'Executed' or not response.ACTIONS.get(plan.get('action'), ('', False))[1]:
            QMessageBox.information(self, 'Undo', 'Only executed, reversible actions can be undone (kill process cannot).')
            return
        if QMessageBox.question(self, 'Undo', 'Undo "%s \u2192 %s"?' % (r['action'], r['target'])) == QMessageBox.Yes:
            self.run_task(response.undo_request, lambda res: (self.notify('MiniSOC undo', '#%s: %s' % (rid, res[1])), self.refresh()), rid)

    def release_isolation(self):
        rid = db.isolation_active()
        if rid and QMessageBox.question(self, 'Release isolation', 'Restore network access for this computer?') == QMessageBox.Yes:
            self.run_task(response.undo_request, lambda res: (QMessageBox.information(self, 'Isolation', res[1]), self.refresh()), rid)

    def show_response(self):
        key = self.rtab.selected_key()
        r = getattr(self, 'resp_rows', {}).get(int(key)) if key and key.isdigit() else None
        if not r:
            self.resp_detail.setPlainText('')
            return
        plan = json.loads(r['plan_json'] or '{}')
        lines = ['Response #%s  \u2022  %s  \u2022  %s' % (r['id'], r['mode'] or 'manual', r['status']),
                 'Action     : %s' % r['action'], 'Target     : %s' % (r['target'] or '\u2013'),
                 'Reason     : %s' % (r['reason'] or '\u2013'),
                 'Will run   : %s' % (response.preview(plan) if plan else 'record only'),
                 'Reversible : %s' % ('yes' if plan and response.ACTIONS.get(plan.get('action'), ('', False))[1] else 'no'),
                 'Requested  : %s    Executed: %s    Undone: %s' % (self.t(r['created_utc']), self.t(r['executed_utc']) or '\u2013',
                                                                  self.t(r['undone_utc']) or '\u2013')]
        if r['expires_utc']:
            lines.append('Expires    : %s' % self.t(r['expires_utc']))
        if r['result']:
            lines += ['', 'Result:'] + ['  ' + x for x in r['result'].split('\n')]
        self.resp_detail.setPlainText('\n'.join(lines))

    def run_task(self, fn, on_done, *args):
        w = TaskWorker(fn, *args)
        w.done.connect(on_done)
        w.failed.connect(lambda m: QMessageBox.warning(self, 'MiniSOC', m))
        w.finished.connect(lambda: self.tasks.remove(w) if w in self.tasks else None)
        self.tasks.append(w)
        w.start()

    def _expired(self, n):
        if n:
            self.notify('MiniSOC', '%d IP block(s) expired and were removed' % n)
            self.refresh()

    def notify(self, title, text):
        if self.tray:
            self.tray.showMessage(title, text, QSystemTrayIcon.Warning, 15000)

    def closeEvent(self, e):
        self.stop()
        for w in [self.worker, self.health_worker] + list(self.tasks):
            if w and w.isRunning():
                w.wait(8000)
        e.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    w = Main()
    w.show()
    sys.exit(app.exec())
