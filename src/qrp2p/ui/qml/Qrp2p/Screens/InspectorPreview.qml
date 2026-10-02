import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// Development preview of the Inspector workspace layout (UI_DESIGN §3.3, §13.1 step 6). It shows
// no protocol data at all: the real Inspector, fed by the trace bus, is M4 work.
Item {
    id: inspector

    property bool split: true

    signal backToChat()

    Rectangle {
        anchors.fill: parent
        color: Theme.canvas
    }
    Divider {
        vertical: true
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        visible: inspector.split
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.s6
        spacing: Theme.s4

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.s3

            AppButton {
                visible: !inspector.split
                kind: "quiet"
                iconName: "arrow-left"
                text: qsTr("Back to chat")
                onClicked: inspector.backToChat()
            }
            AppText {
                text: qsTr("Session Inspector")
                role: "heading"
                Accessible.role: Accessible.Heading
            }
            Tag {
                text: qsTr("LAYOUT PREVIEW")
                kind: "lab"
            }
            Item { Layout.fillWidth: true }
            AppText {
                text: qsTr("Public trace")
                role: "secondary"
            }
        }
        Row {
            spacing: Theme.s1
            Repeater {
                model: [["Timeline", "clock"], ["Messages", "file"], ["Keys", "key-round"], ["Security", "shield"]]
                AppButton {
                    required property var modelData
                    required property int index
                    kind: index === 0 ? "secondary" : "quiet"
                    iconName: modelData[1]
                    text: modelData[0]
                    enabled: false
                }
            }
        }
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: Theme.radiusCard
            color: "transparent"
            border.width: 1
            border.color: Theme.divider

            ColumnLayout {
                anchors.centerIn: parent
                width: Math.min(420, parent.width - Theme.s6 * 2)
                spacing: Theme.s3

                Icon {
                    Layout.alignment: Qt.AlignHCenter
                    name: "panel-right"
                    size: 36
                    color: Theme.textSecondary
                }
                AppText {
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignHCenter
                    text: qsTr("The Inspector arrives in a later version.")
                    role: "title"
                }
                AppText {
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignHCenter
                    text: qsTr("This preview only checks the workspace layout. Nothing here is captured protocol data.")
                    role: "secondary"
                    wrapMode: Text.Wrap
                }
            }
        }
    }
}
