import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// A slim scroll bar that widens under the pointer.
T.ScrollBar {
    id: control

    implicitWidth: hovered || pressed ? 10 : 6
    implicitHeight: hovered || pressed ? 10 : 6
    padding: 2
    minimumSize: 0.08
    visible: size < 1.0 && policy !== T.ScrollBar.AlwaysOff

    contentItem: Rectangle {
        radius: width / 2
        color: Theme.controlBoundary
        opacity: control.pressed ? 0.9 : control.hovered ? 0.7 : control.active ? 0.5 : 0.0

        Behavior on opacity {
            NumberAnimation { duration: Theme.motion }
        }
    }
}
