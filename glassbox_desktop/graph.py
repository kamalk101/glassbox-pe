"""Simple evidence graph canvas for the desktop workbench."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QPen, QFont
from PySide6.QtWidgets import QGraphicsEllipseItem, QGraphicsScene, QGraphicsView, QGraphicsTextItem

from glassbox.schema import Case


class EvidenceGraphView(QGraphicsView):
    """Draw a small evidence graph using Qt graphics primitives."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(self.renderHints().Antialiasing, True)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setScene(QGraphicsScene(self))

    def show_case(self, case: Case) -> None:
        scene = self.scene()
        scene.clear()
        scene.setBackgroundBrush(QBrush(Qt.GlobalColor.darkGray))
        findings = case.findings[:16]
        events = {event.id: event for event in case.events}
        center_y = 0
        left = []
        for index, finding in enumerate(findings):
            y = (index - len(findings) / 2) * 72
            item = self._add_node(f"{finding.rule_id}\n{finding.title[:34]}", -420, y, "#0a84ff")
            left.append((finding, item))
        positions = {}
        for index, finding in enumerate(findings):
            for event_id in finding.evidence:
                positions.setdefault(event_id, 0)
        center_items = []
        for index, (event_id, _count) in enumerate(positions.items()):
            event = events.get(event_id)
            if event is None:
                continue
            y = (index - len(positions) / 2) * 40
            item = self._add_node(f"{event.action}\n{event.target[:34]}", 0, y, "#2f4f6f")
            center_items.append((event, item))
        for finding, left_item in left:
            for event_id in finding.evidence:
                if event_id not in positions:
                    continue
                matching = [item for event, item in center_items if event.id == event_id]
                if matching:
                    scene.addLine(
                        left_item.pos().x() + left_item.boundingRect().width(),
                        left_item.pos().y() + left_item.boundingRect().height() / 2,
                        matching[0].pos().x(),
                        matching[0].pos().y() + matching[0].boundingRect().height() / 2,
                        QPen(Qt.GlobalColor.white, 1),
                    )

    def _add_node(self, text: str, x: float, y: float, color: str):
        scene = self.scene()
        item = QGraphicsEllipseItem(0, 0, 260, 56)
        item.setPos(x, y)
        item.setBrush(QBrush(Qt.GlobalColor.darkBlue))
        item.setPen(QPen(Qt.GlobalColor.white, 1))
        scene.addItem(item)
        label = QGraphicsTextItem(text)
        label.setDefaultTextColor(Qt.GlobalColor.white)
        label.setFont(QFont("Segoe UI", 8))
        label.setTextWidth(240)
        label.setPos(x + 10, y + 8)
        scene.addItem(label)
        return item
