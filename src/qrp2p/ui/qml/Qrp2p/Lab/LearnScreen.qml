import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Learn: the hub of the learning tools that exist so far (UI_DESIGN §3.4). It lists nothing
// that has not landed: the Attack Lab, the Algorithm Lab and the lessons join it later.
Item {
    id: hub

    required property var lab

    signal backToChat()
    signal openLab()

    objectName: "learnScreen"

    function focusFirst() {
        openButton.forceActiveFocus(Qt.TabFocusReason)
    }

    Flickable {
        anchors.fill: parent
        contentHeight: column.implicitHeight + Theme.s8 * 2
        boundsBehavior: Flickable.StopAtBounds
        clip: true
        T.ScrollBar.vertical: AppScrollBar {}

        ColumnLayout {
            id: column
            x: Math.round((parent.width - width) / 2)
            y: Theme.s6
            width: Math.min(Theme.readingWidth, hub.width - Theme.s6 * 2)
            spacing: Theme.s4

            AppButton {
                kind: "quiet"
                compact: true
                iconName: "arrow-left"
                text: qsTr("Back to chat")
                onClicked: hub.backToChat()
            }
            AppText {
                text: qsTr("Learn")
                role: "heading"
                Accessible.role: Accessible.Heading
            }
            AppText {
                Layout.fillWidth: true
                text: qsTr("See the protocol work from the inside. Nothing here touches your contacts or your identity.")
                role: "secondary"
                wrapMode: Text.Wrap
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.topMargin: Theme.s2
                implicitHeight: card.implicitHeight + Theme.s6 * 2
                radius: Theme.radiusCard
                color: Theme.surface
                border.width: 1
                border.color: Theme.divider

                RowLayout {
                    id: card
                    anchors.fill: parent
                    anchors.margins: Theme.s6
                    spacing: Theme.s4

                    Rectangle {
                        Layout.alignment: Qt.AlignTop
                        implicitWidth: 48
                        implicitHeight: 48
                        radius: Theme.radiusControl
                        color: Theme.labFill

                        Icon {
                            anchors.centerIn: parent
                            name: "flask-conical"
                            size: 26
                            color: Theme.labText
                        }
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.s2

                        RowLayout {
                            spacing: Theme.s2
                            AppText {
                                text: qsTr("Solo lab")
                                role: "title"
                            }
                            Tag {
                                text: qsTr("LAB")
                                kind: "lab"
                            }
                        }
                        AppText {
                            Layout.fillWidth: true
                            text: qsTr("Two throwaway identities, Alice and Bob, run the real protocol in this app. Step through the handshake one message at a time, see every key in the Inspector, then fork at any step and do something else.")
                            wrapMode: Text.Wrap
                        }
                        AppText {
                            Layout.fillWidth: true
                            text: qsTr("No network: Alice and Bob are linked in memory. Every value is revealed, including their private keys; yours never appear.")
                            role: "small"
                            wrapMode: Text.Wrap
                        }
                        AppButton {
                            id: openButton
                            objectName: "openSoloLab"
                            Layout.topMargin: Theme.s2
                            kind: "primary"
                            iconName: "flask-conical"
                            text: hub.lab.active ? qsTr("Continue the solo lab") : qsTr("Open the solo lab")
                            onClicked: hub.openLab()
                        }
                    }
                }
            }
        }
    }
}
