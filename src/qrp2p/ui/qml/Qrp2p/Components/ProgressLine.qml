import QtQuick
import Qrp2p.Theme

// Measured progress only (bytes the node reported), never progress invented from time.
Rectangle {
    property real value: 0   // 0..1

    implicitHeight: 4
    radius: 2
    color: Theme.divider
    Accessible.role: Accessible.ProgressBar
    Accessible.name: Math.round(value * 100) + "%"

    Rectangle {
        width: parent.width * Math.max(0, Math.min(1, parent.value))
        height: parent.height
        radius: parent.radius
        color: Theme.text
    }
}
