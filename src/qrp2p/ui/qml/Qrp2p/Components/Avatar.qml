import QtQuick
import Qrp2p.Theme

// A compact identity circle with the name's initial. It is never the trust signal: trust is
// always the explicit badge next to the name (UI_DESIGN §3.1).
Rectangle {
    id: avatar

    property string initial: "?"
    property int size: 36
    property int unread: 0

    implicitWidth: size
    implicitHeight: size
    radius: size / 2
    color: Theme.avatarFill
    Accessible.ignored: true

    AppText {
        anchors.centerIn: parent
        text: avatar.initial
        font.pixelSize: Math.round(avatar.size * 0.42)
        font.weight: Theme.weightMedium
        color: Theme.text
    }

    Rectangle {
        visible: avatar.unread > 0
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.rightMargin: -4
        anchors.topMargin: -4
        height: Math.max(18, badge.implicitHeight + 4)
        width: Math.max(height, badge.implicitWidth + 10)
        radius: height / 2
        color: Theme.primaryFill
        border.width: 2
        border.color: Theme.canvas

        AppText {
            id: badge
            anchors.centerIn: parent
            text: avatar.unread > 99 ? "99+" : String(avatar.unread)
            role: "label"
            font.pixelSize: Theme.sizeLabel - 1
            color: Theme.primaryText
        }
    }
}
