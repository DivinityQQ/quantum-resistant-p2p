import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// A row of the conversation: an optional day label, then a chat bubble, a file card or a local
// note, then (at a group's end) the time and the delivery state.
Item {
    id: row

    required property string entryId
    required property string kind
    required property string direction
    required property string text
    required property string timeText
    required property string status
    required property string statusText
    required property bool glassBox
    required property string fileId
    required property string fileName
    required property string fileSizeText
    required property string fileStatus
    required property string fileStateText
    required property real fileProgress
    required property string filePath
    required property string dayLabel
    required property bool groupStart
    required property bool groupEnd
    required property bool showMeta

    property var conversation
    property int columnWidth: 600

    signal saveTo(string fileId)
    signal verify()

    readonly property bool outgoing: direction === "out"
    readonly property real bubbleMax: Math.round(columnWidth * 0.75)

    width: ListView.view ? ListView.view.width : columnWidth
    height: column.implicitHeight + (groupStart ? Theme.s3 : 2)

    ColumnLayout {
        id: column
        width: row.columnWidth
        x: Math.round((row.width - width) / 2)
        y: row.groupStart ? Theme.s3 : 2
        spacing: Theme.s1

        // Day label
        RowLayout {
            visible: row.dayLabel !== ""
            Layout.fillWidth: true
            Layout.topMargin: Theme.s3
            Layout.bottomMargin: Theme.s3
            spacing: Theme.s3

            Divider { Layout.fillWidth: true }
            AppText {
                text: row.dayLabel
                role: "small"
            }
            Divider { Layout.fillWidth: true }
        }

        ChatBubble {
            visible: row.kind === "chat"
            Layout.alignment: row.outgoing ? Qt.AlignRight : Qt.AlignLeft
            text: row.kind === "chat" ? row.text : ""
            outgoing: row.outgoing
            groupStart: row.groupStart
            groupEnd: row.groupEnd
            maxWidth: row.bubbleMax
        }

        Loader {
            active: row.kind === "file"
            visible: active
            Layout.alignment: row.outgoing ? Qt.AlignRight : Qt.AlignLeft
            sourceComponent: FileCard {
                conversation: row.conversation
                entryId: row.entryId
                outgoing: row.outgoing
                fileId: row.fileId
                fileName: row.fileName
                fileSizeText: row.fileSizeText
                fileStatus: row.fileStatus
                fileStateText: row.fileStateText
                fileProgress: row.fileProgress
                filePath: row.filePath
                maxWidth: row.bubbleMax
                onSaveTo: id => row.saveTo(id)
            }
        }

        // A local note: never a peer message (DESIGN §5.3 rule 3).
        Rectangle {
            visible: row.kind === "identity_changed"
            Layout.alignment: Qt.AlignHCenter
            Layout.maximumWidth: row.columnWidth
            Layout.topMargin: Theme.s2
            Layout.bottomMargin: Theme.s2
            implicitWidth: note.implicitWidth + Theme.s4 * 2
            implicitHeight: note.implicitHeight + Theme.s2 * 2
            radius: Theme.radiusControl
            color: Theme.surfaceSubtle

            RowLayout {
                id: note
                anchors.centerIn: parent
                width: Math.min(implicitWidth, row.columnWidth - Theme.s4 * 2)
                spacing: Theme.s2

                Icon {
                    name: "shield-alert"
                    color: Theme.textSecondary
                    size: Theme.iconSize - 2
                }
                AppText {
                    Layout.fillWidth: true
                    Layout.maximumWidth: row.columnWidth - 160
                    text: row.kind === "identity_changed" ? row.text : ""
                    role: "small"
                    wrapMode: Text.Wrap
                }
                AppButton {
                    kind: "quiet"
                    compact: true
                    text: qsTr("Verify")
                    onClicked: row.verify()
                }
            }
        }

        // Time and delivery state
        RowLayout {
            visible: row.showMeta && row.kind !== "identity_changed"
            Layout.alignment: row.outgoing ? Qt.AlignRight : Qt.AlignLeft
            Layout.leftMargin: row.outgoing ? 0 : Theme.s3
            Layout.rightMargin: row.outgoing ? Theme.s1 : 0
            spacing: Theme.s2

            Tag {
                visible: row.glassBox
                text: "GLASS-BOX"
                kind: "exposure"
            }
            AppText {
                text: row.timeText
                role: "small"
            }
            AppText {
                visible: row.statusText !== ""
                text: row.statusText
                role: "small"
                color: row.status === "failed" ? Theme.dangerText : Theme.textSecondary
            }
            AppButton {
                visible: row.status === "failed" && row.kind === "chat"
                kind: "quiet"
                compact: true
                text: qsTr("Send again")
                onClicked: row.conversation.retry(row.entryId)
            }
        }
    }
}
