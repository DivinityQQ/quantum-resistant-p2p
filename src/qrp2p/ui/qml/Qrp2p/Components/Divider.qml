import QtQuick
import Qrp2p.Theme

// Decorative separation only; never the boundary of a control (UI_DESIGN §4.2).
Rectangle {
    property bool vertical: false

    implicitWidth: vertical ? 1 : 100
    implicitHeight: vertical ? 100 : 1
    color: Theme.divider
    Accessible.ignored: true
}
