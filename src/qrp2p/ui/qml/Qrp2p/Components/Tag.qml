import QtQuick
import Qrp2p.Theme

// A short persistent label such as GLASS-BOX: text and colour together, never colour alone.
Rectangle {
    id: tag

    property string text
    // exposure | lab | danger | neutral
    property string kind: "neutral"
    property string iconName: ""

    implicitWidth: row.implicitWidth + Theme.s2 * 2
    implicitHeight: row.implicitHeight + 4
    radius: Theme.radiusTight
    color: kind === "exposure" ? Theme.exposureFill
        : kind === "lab" ? Theme.labFill
        : kind === "danger" ? Theme.dangerFill : Theme.surfaceSubtle
    Accessible.role: Accessible.StaticText
    Accessible.name: text

    Row {
        id: row
        anchors.centerIn: parent
        spacing: Theme.s1

        Icon {
            visible: tag.iconName !== ""
            name: tag.iconName
            size: Theme.sizeLabel + 2
            color: label.color
            anchors.verticalCenter: parent.verticalCenter
        }
        AppText {
            id: label
            text: tag.text
            role: "label"
            font.pixelSize: Theme.sizeLabel - 1
            font.letterSpacing: 0.4
            color: tag.kind === "exposure" ? Theme.exposureText
                : tag.kind === "lab" ? Theme.labText
                : tag.kind === "danger" ? Theme.dangerText : Theme.textSecondary
            anchors.verticalCenter: parent.verticalCenter
        }
    }
}
