import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// An on/off setting with its label; the description underneath says what it changes.
T.Switch {
    id: control

    property string description: ""

    implicitWidth: Math.max(implicitContentWidth + leftPadding + rightPadding, 200)
    implicitHeight: Math.max(implicitContentHeight, indicator.implicitHeight) + topPadding + bottomPadding
    padding: Theme.s1
    spacing: Theme.s3
    hoverEnabled: true
    focusPolicy: Qt.StrongFocus
    font.family: Theme.family
    font.pixelSize: Theme.sizeBody
    Accessible.name: text
    Accessible.description: description

    indicator: Rectangle {
        implicitWidth: 38
        implicitHeight: 22
        x: control.width - width - control.rightPadding
        y: control.topPadding + (Theme.sizeBody * 1.4 - height) / 2
        radius: height / 2
        color: control.checked ? (control.enabled ? Theme.primaryFill : Theme.controlBoundary)
            : control.hovered ? Theme.pressedFill : Theme.surfaceSubtle
        border.width: control.checked ? 0 : 1
        border.color: Theme.controlBoundary

        Rectangle {
            x: control.checked ? parent.width - width - 3 : 3
            anchors.verticalCenter: parent.verticalCenter
            width: 16
            height: 16
            radius: 8
            color: control.checked ? Theme.primaryText : Theme.controlBoundary

            Behavior on x {
                NumberAnimation { duration: Theme.motionFast; easing.type: Easing.OutCubic }
            }
        }

        FocusRing {
            visible: control.visualFocus
            cornerRadius: parent.radius
        }
    }

    contentItem: Column {
        rightPadding: control.indicator.width + control.spacing
        spacing: 2

        AppText {
            width: parent.width - parent.rightPadding
            text: control.text
            font: control.font
            color: control.enabled ? Theme.text : Theme.textSecondary
            wrapMode: Text.Wrap
        }
        AppText {
            width: parent.width - parent.rightPadding
            visible: control.description !== ""
            text: control.description
            role: "small"
            wrapMode: Text.Wrap
        }
    }
}
