import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// The standard button: primary, secondary, quiet, danger or exposure (glass-box consent).
// While busy it ignores presses (no second submission) and never implies success.
T.Button {
    id: control

    property string kind: "secondary"
    property string iconName: ""
    property bool busy: false
    property bool compact: false
    property string toolTipText: ""

    readonly property color foreground: !enabled ? Theme.textSecondary
        : kind === "primary" ? Theme.primaryText
        : kind === "danger" ? Theme.dangerText
        : kind === "exposure" ? Theme.exposureText
        : Theme.text

    implicitHeight: compact ? Math.round(Theme.controlHeight * 0.84) : Theme.controlHeight
    implicitWidth: Math.max(implicitHeight, implicitContentWidth + leftPadding + rightPadding)
    leftPadding: text ? (compact ? Theme.s3 : Theme.s4) : 0
    rightPadding: leftPadding
    focusPolicy: Qt.StrongFocus
    hoverEnabled: true
    font.family: Theme.family
    font.pixelSize: compact ? Theme.sizeSmall : Theme.sizeBody
    font.weight: Theme.weightMedium
    Accessible.name: text || toolTipText
    Accessible.description: toolTipText

    contentItem: Item {
        implicitWidth: row.implicitWidth
        implicitHeight: row.implicitHeight

        Row {
            id: row
            anchors.centerIn: parent
            spacing: Theme.s2

            Spinner {
                visible: control.busy
                size: Theme.iconSize - 2
                color: control.foreground
                anchors.verticalCenter: parent.verticalCenter
            }
            Icon {
                visible: !control.busy && control.iconName !== ""
                name: control.iconName
                size: control.compact ? Theme.iconSize - 2 : Theme.iconSize
                color: control.foreground
                anchors.verticalCenter: parent.verticalCenter
            }
            AppText {
                visible: control.text !== ""
                text: control.text
                font: control.font
                color: control.foreground
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    background: Rectangle {
        radius: Theme.radiusControl
        color: {
            if (!control.enabled)
                return control.kind === "quiet" ? "transparent" : Theme.surfaceSubtle
            switch (control.kind) {
            case "primary":
                return control.down ? Theme.text : control.hovered ? Theme.primaryHover : Theme.primaryFill
            case "danger":
                return control.down || control.hovered ? Qt.darker(Theme.dangerFill, Theme.dark ? 0.85 : 1.04) : Theme.dangerFill
            case "exposure":
                return control.down || control.hovered ? Qt.darker(Theme.exposureFill, Theme.dark ? 0.85 : 1.04) : Theme.exposureFill
            case "quiet":
                return control.down ? Theme.pressedFill : control.hovered ? Theme.hoverFill : "transparent"
            default:
                return control.down ? Theme.pressedFill : control.hovered ? Theme.hoverFill : Theme.surface
            }
        }
        border.width: control.kind === "secondary" ? 1 : 0
        border.color: control.enabled ? Theme.controlBoundary : Theme.divider

        FocusRing {
            visible: control.visualFocus
        }
    }

    // While busy: swallow presses and the keys that would click, so nothing submits twice
    // (Tab and the rest still move on).
    function clickKey(event) {
        return event.key === Qt.Key_Space || event.key === Qt.Key_Return
            || event.key === Qt.Key_Enter || event.key === Qt.Key_Select
    }
    Keys.onPressed: event => event.accepted = control.busy && clickKey(event)
    Keys.onReleased: event => event.accepted = control.busy && clickKey(event)

    MouseArea {
        anchors.fill: parent
        enabled: control.busy
        acceptedButtons: Qt.AllButtons
        cursorShape: Qt.BusyCursor
    }

    AppToolTip {
        text: control.toolTipText
        visible: control.hovered && control.toolTipText !== "" && control.text === ""
    }
}
