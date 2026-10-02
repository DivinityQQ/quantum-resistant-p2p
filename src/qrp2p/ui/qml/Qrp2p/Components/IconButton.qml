import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// An icon-only action. Its name is mandatory: it is the accessible name and the tooltip.
T.Button {
    id: control

    required property string label
    property string iconName
    property color iconColor: Theme.text
    property bool active: false

    implicitWidth: Theme.controlHeight
    implicitHeight: Theme.controlHeight
    padding: 0
    focusPolicy: Qt.StrongFocus
    hoverEnabled: true
    Accessible.name: label

    contentItem: Item {
        Icon {
            anchors.centerIn: parent
            name: control.iconName
            color: control.enabled ? control.iconColor : Theme.textSecondary
        }
    }

    background: Rectangle {
        radius: Theme.radiusControl
        color: control.down ? Theme.pressedFill
            : control.hovered || control.active ? Theme.hoverFill : "transparent"

        FocusRing {
            visible: control.visualFocus
        }
    }

    AppToolTip {
        text: control.label
        visible: control.hovered
    }
}
