import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme

// A menu entry; danger entries are named as such, not only coloured.
T.MenuItem {
    id: control

    property bool danger: false
    property string iconName: ""
    property string shortcutText: ""

    implicitWidth: row.implicitWidth + leftPadding + rightPadding
    implicitHeight: Math.max(Theme.controlHeight, row.implicitHeight + topPadding + bottomPadding)
    height: visible ? implicitHeight : 0  // a hidden entry takes no room in its menu
    leftPadding: Theme.s3
    rightPadding: Theme.s3
    hoverEnabled: true
    Accessible.name: text

    contentItem: Item {
        implicitWidth: row.implicitWidth
        implicitHeight: row.implicitHeight

        RowLayout {
            id: row
            anchors.fill: parent
            spacing: Theme.s3

            Icon {
                visible: control.iconName !== ""
                name: control.iconName
                color: label.color
                size: Theme.iconSize - 2
            }
            AppText {
                id: label
                Layout.fillWidth: true
                text: control.text
                color: !control.enabled ? Theme.textSecondary : control.danger ? Theme.dangerText : Theme.text
            }
            AppText {
                visible: control.shortcutText !== ""
                text: control.shortcutText
                role: "small"
                Layout.leftMargin: Theme.s6
            }
        }
    }

    background: Rectangle {
        radius: Theme.radiusTight + 2
        color: control.down ? Theme.pressedFill
            : control.highlighted || control.hovered ? Theme.hoverFill : "transparent"

        FocusRing {
            visible: control.visualFocus
            cornerRadius: Theme.radiusTight + 2
        }
    }
}
