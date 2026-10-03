import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme

// An inline notice inside a pane: connection stages, failures, exposure. Local and calm, never
// a full-screen alarm (UI_DESIGN §2.6).
Rectangle {
    id: banner

    property string text
    // neutral | danger | exposure | success | lab
    property string kind: "neutral"
    property string iconName: kind === "danger" ? "circle-alert" : kind === "exposure" ? "eye"
        : kind === "lab" ? "flask-conical" : "info"
    property bool busy: false
    property bool dismissible: false
    default property alias actions: actionRow.data

    signal dismissed()

    readonly property color foreground: kind === "danger" ? Theme.dangerText
        : kind === "exposure" ? Theme.exposureText
        : kind === "lab" ? Theme.labText
        : kind === "success" ? Theme.success : Theme.text

    implicitHeight: Math.max(Theme.controlHeight, layout.implicitHeight + Theme.s2 * 2)
    radius: Theme.radiusControl
    color: kind === "danger" ? Theme.dangerFill : kind === "exposure" ? Theme.exposureFill
        : kind === "lab" ? Theme.labFill : Theme.surfaceSubtle
    Accessible.role: Accessible.AlertMessage
    Accessible.name: text

    // Icons sit on the first line of text, so a wrapped message still reads from its icon.
    readonly property real _lineOffset: Math.max(0, (message.font.pixelSize * 1.21 - Theme.iconSize) / 2)

    RowLayout {
        id: layout
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: Theme.s3
        anchors.rightMargin: Theme.s2
        spacing: Theme.s3

        Spinner {
            visible: banner.busy
            Layout.alignment: message.lineCount > 1 ? Qt.AlignTop : Qt.AlignVCenter
            Layout.topMargin: message.lineCount > 1 ? banner._lineOffset : 0
            color: banner.foreground
        }
        Icon {
            visible: !banner.busy
            Layout.alignment: message.lineCount > 1 ? Qt.AlignTop : Qt.AlignVCenter
            Layout.topMargin: message.lineCount > 1 ? banner._lineOffset : 0
            name: banner.iconName
            color: banner.foreground
        }
        AppText {
            id: message
            Layout.fillWidth: true
            Layout.alignment: lineCount > 1 ? Qt.AlignTop : Qt.AlignVCenter
            text: banner.text
            color: banner.foreground
            wrapMode: Text.Wrap
        }
        Row {
            id: actionRow
            Layout.alignment: Qt.AlignVCenter
            spacing: Theme.s2
        }
        IconButton {
            visible: banner.dismissible
            Layout.alignment: Qt.AlignVCenter
            label: qsTr("Dismiss")
            iconName: "x"
            iconColor: banner.foreground
            Layout.preferredWidth: Theme.controlHeight - 6
            Layout.preferredHeight: Theme.controlHeight - 6
            onClicked: banner.dismissed()
        }
    }
}
