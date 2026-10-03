import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

T.MenuSeparator {
    implicitWidth: 200
    implicitHeight: Theme.s2 + 1
    height: visible ? implicitHeight : 0
    topPadding: Theme.s1
    bottomPadding: Theme.s1
    contentItem: Rectangle {
        implicitHeight: 1
        color: Theme.divider
    }
}
