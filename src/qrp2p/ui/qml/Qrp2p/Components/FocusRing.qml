import QtQuick
import Qrp2p.Theme

// The keyboard-focus outline: distinct from hover, pressed and selected (UI_DESIGN §5).
Rectangle {
    property Item target: parent
    property real cornerRadius: Theme.radiusControl

    anchors.fill: target
    anchors.margins: -3
    radius: cornerRadius + 3
    color: "transparent"
    border.width: 2
    border.color: Theme.focus
}
