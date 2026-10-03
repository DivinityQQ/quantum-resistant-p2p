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

    Component.onCompleted: lab.refreshRecordings()

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

            // -- saved recordings ---------------------------------------------------------------
            AppText {
                Layout.topMargin: Theme.s4
                text: qsTr("Recordings")
                role: "title"
                Accessible.role: Accessible.Heading
            }
            AppText {
                Layout.fillWidth: true
                text: qsTr("A saved solo-lab run replays exactly and can be forked. A saved glass-box session is EXPOSED: every key and message in it can be read. Recordings are sealed with your vault's key.")
                role: "secondary"
                wrapMode: Text.Wrap
            }
            AppText {
                Layout.fillWidth: true
                visible: recordings.count === 0
                text: qsTr("Nothing saved yet. Save a run from the solo lab, or a glass-box session from the Inspector.")
                role: "small"
                wrapMode: Text.Wrap
            }
            Repeater {
                id: recordings
                model: hub.lab.recordings

                Rectangle {
                    id: entry

                    required property string key
                    required property string title
                    required property string kind
                    required property string detail
                    property bool confirming: false

                    objectName: "recording-" + key
                    Layout.fillWidth: true
                    implicitHeight: row.implicitHeight + Theme.s3 * 2
                    radius: Theme.radiusControl
                    color: Theme.surface
                    border.width: 1
                    border.color: entry.kind === "glass_box" ? Theme.exposureText : Theme.divider

                    RowLayout {
                        id: row
                        anchors.fill: parent
                        anchors.margins: Theme.s3
                        spacing: Theme.s3

                        Icon {
                            Layout.alignment: Qt.AlignTop
                            name: entry.kind === "lab" ? "flask-conical"
                                : entry.kind === "glass_box" ? "eye" : "circle-alert"
                            color: entry.kind === "lab" ? Theme.labText
                                : entry.kind === "glass_box" ? Theme.exposureText : Theme.dangerText
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.s2
                                AppText {
                                    Layout.fillWidth: true
                                    text: entry.title
                                    font.weight: Theme.weightMedium
                                    elide: Text.ElideRight
                                }
                                Tag {
                                    visible: entry.kind === "glass_box"
                                    text: qsTr("EXPOSED")
                                    kind: "exposure"
                                }
                                Tag {
                                    visible: entry.kind === "lab"
                                    text: qsTr("LAB")
                                    kind: "lab"
                                }
                            }
                            AppText {
                                Layout.fillWidth: true
                                text: entry.detail
                                role: "small"
                                wrapMode: Text.Wrap
                            }
                        }
                        AppButton {
                            objectName: "openRecording-" + entry.key
                            visible: entry.kind !== "unreadable" && !entry.confirming
                            compact: true
                            text: entry.kind === "lab" ? qsTr("Replay") : qsTr("View")
                            enabled: !hub.lab.busy
                            onClicked: {
                                hub.lab.openRecording(entry.key)
                                hub.openLab()
                            }
                        }
                        AppButton {
                            objectName: "deleteRecording-" + entry.key
                            compact: true
                            kind: entry.confirming ? "danger" : "quiet"
                            iconName: "trash-2"
                            text: entry.confirming ? qsTr("Delete for good") : ""
                            toolTipText: qsTr("Delete this recording")
                            onClicked: {
                                if (entry.confirming)
                                    hub.lab.deleteRecording(entry.key)
                                entry.confirming = !entry.confirming
                            }
                        }
                        AppButton {
                            visible: entry.confirming
                            compact: true
                            kind: "quiet"
                            text: qsTr("Keep")
                            onClicked: entry.confirming = false
                        }
                    }
                }
            }
        }
    }
}
