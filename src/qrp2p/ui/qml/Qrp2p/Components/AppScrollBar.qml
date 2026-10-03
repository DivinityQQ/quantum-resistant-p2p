import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// A slim scroll bar that widens under the pointer. Attached to a Flickable it sits over the
// content's right edge, so the content leaves room for it: Theme.scrollGutter, always, when the
// content wraps (its height depends on its width); `gutter`, zero while hidden, when it does not.
T.ScrollBar {
    id: control

    readonly property int gutter: visible ? Theme.scrollGutter : 0

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
