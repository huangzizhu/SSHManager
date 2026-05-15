from __future__ import annotations

import re
from collections.abc import Callable

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QFont, QKeyEvent
from PyQt6.QtWidgets import QApplication, QLabel, QPlainTextEdit, QVBoxLayout, QWidget

try:
    import pyte
except Exception:  # noqa: BLE001
    pyte = None


ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]|\x1B\].*?(?:\x07|\x1B\\)")


class _TerminalView(QPlainTextEdit):
    def __init__(self, send_text: Callable[[str], None], send_control: Callable[[str], None], parent=None) -> None:
        super().__init__(parent)
        self._send_text = send_text
        self._send_control = send_control
        self.setReadOnly(False)
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(QFont("Monospace", 11))

    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        mod = event.modifiers()

        if mod & Qt.KeyboardModifier.ControlModifier:
            if key == Qt.Key.Key_C:
                if self.textCursor().hasSelection():
                    self.copy()
                    return
                self._send_control("c")
                return
            if key == Qt.Key.Key_L:
                self._send_text("\x0c")
                return
            if key == Qt.Key.Key_V:
                text = QApplication.clipboard().text()
                if text:
                    self._send_text(text)
                return
        if mod & Qt.KeyboardModifier.ShiftModifier and mod & Qt.KeyboardModifier.ControlModifier:
            if key == Qt.Key.Key_C:
                self.copy()
                return
            if key == Qt.Key.Key_V:
                self.paste()
                return

        mapping = {
            Qt.Key.Key_Return: "\r",
            Qt.Key.Key_Enter: "\r",
            Qt.Key.Key_Backspace: "\x7f",
            Qt.Key.Key_Up: "\x1b[A",
            Qt.Key.Key_Down: "\x1b[B",
            Qt.Key.Key_Right: "\x1b[C",
            Qt.Key.Key_Left: "\x1b[D",
            Qt.Key.Key_Home: "\x1b[H",
            Qt.Key.Key_End: "\x1b[F",
            Qt.Key.Key_PageUp: "\x1b[5~",
            Qt.Key.Key_PageDown: "\x1b[6~",
            Qt.Key.Key_Tab: "\t",
        }
        if key in mapping:
            self._send_text(mapping[key])
            return

        text = event.text()
        if text:
            self._send_text(text)
            return

        super().keyPressEvent(event)


class TerminalWindow(QWidget):
    def __init__(
        self,
        *,
        server_label: str,
        send_text: Callable[[str], None],
        send_control: Callable[[str], None],
        read_output: Callable[[], str],
        is_alive: Callable[[], bool],
        parent=None,
    ) -> None:
        super().__init__(None)
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setWindowFlag(Qt.WindowType.WindowMinMaxButtonsHint, True)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, True)
        self.setWindowTitle(f"Terminal - {server_label}")
        self.resize(1050, 680)

        self._read_output = read_output
        self._is_alive = is_alive

        self._status = QLabel("Connected")
        self._view = _TerminalView(send_text, send_control, self)

        layout = QVBoxLayout(self)
        layout.addWidget(self._status)
        layout.addWidget(self._view)

        self._screen = None
        self._stream = None
        if pyte is not None:
            self._screen = pyte.Screen(200, 3000)
            self._stream = pyte.Stream(self._screen)

        self._timer = QTimer(self)
        self._timer.setInterval(80)
        self._timer.timeout.connect(self._poll_output)
        self._timer.start()

    def _should_follow_tail(self) -> bool:
        bar = self._view.verticalScrollBar()
        return (bar.maximum() - bar.value()) <= 6

    def _scroll_to_bottom(self) -> None:
        bar = self._view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _poll_output(self) -> None:
        if not self._is_alive():
            self._status.setText("Disconnected")
            self._timer.stop()

        data = self._read_output()
        if not data:
            return
        follow_tail = self._should_follow_tail()

        if self._stream and self._screen:
            self._stream.feed(data)
            lines = [line.rstrip() for line in self._screen.display]
            self._view.setPlainText("\n".join(lines))
            if follow_tail:
                self._scroll_to_bottom()
            return

        clean = ANSI_RE.sub("", data)
        self._view.moveCursor(self._view.textCursor().MoveOperation.End)
        self._view.insertPlainText(clean)
        if follow_tail:
            self._scroll_to_bottom()

    def closeEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        super().closeEvent(event)
