import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

AppDialog {
    id: dialog

    readonly property string mod: Qt.platform.os === "osx" ? "⌘" : "Ctrl+"

    titleText: qsTr("Keyboard shortcuts")
    iconName: "keyboard"

    GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: Theme.s6
        rowSpacing: Theme.s2

        Repeater {
            model: [
                [qsTr("Send the message"), qsTr("Enter")],
                [qsTr("New line"), qsTr("Shift+Enter")],
                [qsTr("All contacts"), dialog.mod + "K"],
                [qsTr("Connect to someone"), dialog.mod + "N"],
                [qsTr("Settings"), dialog.mod + ","],
                [qsTr("Session Inspector"), dialog.mod + "I"],
                [qsTr("Lock"), dialog.mod + "L"]
            ]

            delegate: Item {
                required property var modelData
                Layout.columnSpan: 2
                Layout.fillWidth: true
                implicitHeight: line.implicitHeight

                RowLayout {
                    id: line
                    anchors.fill: parent
                    AppText {
                        Layout.fillWidth: true
                        text: parent.parent.modelData[0]
                    }
                    AppText {
                        text: parent.parent.modelData[1]
                        role: "mono"
                    }
                }
            }
        }
    }

    actions: [
        AppButton {
            kind: "primary"
            text: qsTr("Close")
            onClicked: dialog.close()
        }
    ]
}
