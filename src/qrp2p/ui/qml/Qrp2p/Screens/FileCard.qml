import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// A file transfer: name, actual size, measured progress and only the actions that make sense
// now. Received files never open on their own (DESIGN §9).
Rectangle {
    id: card

    required property var conversation
    required property string entryId
    required property bool outgoing
    required property string fileId
    required property string fileName
    required property string fileSizeText
    required property string fileStatus
    required property string fileStateText
    required property real fileProgress
    required property string filePath
    property real maxWidth: 420

    signal saveTo(string fileId)

    readonly property bool offeredToUs: !outgoing && fileStatus === "offered"
    readonly property bool cancellable: fileStatus === "accepted" || fileStatus === "transferring"
        || (outgoing && fileStatus === "offered")
    readonly property bool failedState: fileStatus === "failed" || fileStatus === "cancelled"

    implicitWidth: Math.min(maxWidth, 440)
    implicitHeight: layout.implicitHeight + Theme.s3 * 2
    radius: Theme.radiusCard
    color: outgoing ? Theme.surface : Theme.surfaceSubtle
    border.width: outgoing ? 1 : 0
    border.color: Theme.divider
    Accessible.role: Accessible.Grouping
    Accessible.name: qsTr("File %1, %2, %3").arg(fileName).arg(fileSizeText).arg(fileStateText)

    ColumnLayout {
        id: layout
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: Theme.s3
        spacing: Theme.s3

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.s3

            Rectangle {
                Layout.preferredWidth: 44
                Layout.preferredHeight: 44
                radius: Theme.radiusControl
                color: card.outgoing ? Theme.surfaceSubtle : Theme.surface

                Icon {
                    anchors.centerIn: parent
                    name: card.failedState ? "circle-alert" : card.fileStatus === "complete" ? "check" : "file"
                    color: card.failedState ? Theme.dangerText : Theme.text
                }
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2

                AppText {
                    Layout.fillWidth: true
                    text: card.fileName
                    font.weight: Theme.weightMedium
                    elide: Text.ElideMiddle
                }
                AppText {
                    Layout.fillWidth: true
                    text: card.fileStatus === "transferring" ? card.fileStateText
                        : card.fileSizeText + "  ·  " + card.fileStateText
                    role: "small"
                    color: card.failedState ? Theme.dangerText : Theme.textSecondary
                    elide: Text.ElideRight
                }
            }
        }
        ProgressLine {
            Layout.fillWidth: true
            visible: card.fileStatus === "transferring"
            value: Math.max(0, card.fileProgress)
        }
        Flow {
            Layout.fillWidth: true
            visible: card.offeredToUs || card.cancellable || (card.fileStatus === "complete" && card.filePath !== "")
            spacing: Theme.s2
            layoutDirection: Qt.RightToLeft

            AppButton {
                visible: card.offeredToUs
                kind: "primary"
                compact: true
                text: qsTr("Accept")
                onClicked: card.conversation.acceptFile(card.fileId)
            }
            AppButton {
                visible: card.offeredToUs
                kind: "quiet"
                compact: true
                text: qsTr("Save to…")
                onClicked: card.saveTo(card.fileId)
            }
            AppButton {
                visible: card.offeredToUs
                kind: "quiet"
                compact: true
                text: qsTr("Decline")
                onClicked: card.conversation.declineFile(card.fileId)
            }
            AppButton {
                visible: card.cancellable
                kind: "quiet"
                compact: true
                text: qsTr("Cancel")
                onClicked: card.conversation.cancelFile(card.fileId)
            }
            AppButton {
                visible: card.fileStatus === "complete" && card.filePath !== ""
                kind: "quiet"
                compact: true
                iconName: "folder-open"
                text: qsTr("Show in folder")
                onClicked: card.conversation.showFile(card.entryId)
            }
        }
    }

    AppToolTip {
        visible: nameHover.hovered
        text: card.fileName
    }
    HoverHandler {
        id: nameHover
    }
}
