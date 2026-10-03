import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// One lab node, Alice or Bob: its session state and what it can do now. Each action is one
// lab step; what it queued is sealed and waits in flight until a step delivers it.
Rectangle {
    id: node

    required property var lab
    required property string side       // alice | bob
    readonly property bool alice: side === "alice"
    readonly property bool open: alice ? lab.aliceOpen : lab.bobOpen
    readonly property var received: alice ? lab.aliceReceived : lab.bobReceived
    readonly property string person: alice ? qsTr("Alice") : qsTr("Bob")

    objectName: "labNode-" + side
    implicitHeight: column.implicitHeight + Theme.s3 * 2
    radius: Theme.radiusCard
    color: Theme.surface
    border.width: 1
    border.color: Theme.divider

    ColumnLayout {
        id: column
        anchors.fill: parent
        anchors.margins: Theme.s3
        spacing: Theme.s2

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.s2

            Avatar {
                initial: node.alice ? "A" : "B"
                size: 32
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 0
                AppText {
                    text: node.person
                    font.weight: Theme.weightMedium
                }
                AppText {
                    text: (node.alice ? qsTr("Initiator") : qsTr("Responder")) + " · "
                        + (node.open ? qsTr("session open") : node.lab.phase === "ready"
                            ? qsTr("not started") : qsTr("no open session"))
                    role: "small"
                }
            }
        }

        // Bob's admission decision, when the handshake waits for it.
        RowLayout {
            Layout.fillWidth: true
            visible: !node.alice && node.lab.deciding
            spacing: Theme.s2

            AppText {
                Layout.fillWidth: true
                text: qsTr("Alice is authenticated. Admit her?")
                role: "small"
                wrapMode: Text.Wrap
            }
            AppButton {
                objectName: "labAdmit"
                compact: true
                kind: "primary"
                text: qsTr("Admit")
                enabled: !node.lab.busy
                onClicked: node.lab.decide(true)
            }
            AppButton {
                compact: true
                text: qsTr("Decline")
                enabled: !node.lab.busy
                onClicked: node.lab.decide(false)
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.s1

            AppTextField {
                id: message
                objectName: "labChat-" + node.side
                Layout.fillWidth: true
                implicitWidth: 120
                placeholderText: node.open ? qsTr("Message from %1").arg(node.person) : qsTr("No session yet")
                enabled: node.open
                maximumLength: 4000
                onAccepted: send()

                function send() {
                    if (node.lab.chat(node.side, text))
                        clear()
                }
            }
            IconButton {
                label: qsTr("Send from %1").arg(node.person)
                iconName: "send-horizontal"
                enabled: node.open && message.text.trim() !== "" && !node.lab.busy
                onClicked: message.send()
            }
        }

        Flow {
            Layout.fillWidth: true
            spacing: Theme.s1

            AppButton {
                compact: true
                kind: "secondary"
                iconName: "refresh-cw"
                text: qsTr("KeyUpdate")
                toolTipText: qsTr("Move %1's sending direction to new keys").arg(node.person)
                enabled: node.open && !node.lab.busy
                onClicked: node.lab.keyUpdate(node.side)
            }
            AppButton {
                objectName: "labRekey"
                visible: node.alice
                compact: true
                kind: "secondary"
                iconName: "key-round"
                text: qsTr("PQ rekey")
                enabled: node.lab.canRekey && !node.lab.busy
                onClicked: node.lab.rekey()
            }
            AppButton {
                compact: true
                kind: "quiet"
                iconName: "unplug"
                text: qsTr("Close")
                enabled: node.open && !node.lab.busy
                onClicked: node.lab.closeSession(node.side)
            }
        }

        AppText {
            Layout.fillWidth: true
            visible: node.received.length > 0
            text: qsTr("Received: %1").arg(node.received.map(t => "“" + t + "”").join(", "))
            role: "small"
            wrapMode: Text.Wrap
            maximumLineCount: 3
            elide: Text.ElideRight
        }
    }
}
