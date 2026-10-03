import QtQuick
import Qrp2p.Theme

// Availability as a small mark; always shown next to its words, never alone.
Rectangle {
    // online | connecting | waiting | nearby | blocked | offline
    property string presence: "offline"

    implicitWidth: 8
    implicitHeight: 8
    radius: 4
    color: presence === "online" ? Theme.online
        : presence === "nearby" || presence === "connecting" || presence === "waiting" ? "transparent"
        : Theme.controlBoundary
    border.width: presence === "online" ? 0 : 1.5
    border.color: presence === "blocked" ? Theme.dangerText
        : presence === "online" ? Theme.online : Theme.controlBoundary
    Accessible.ignored: true
}
