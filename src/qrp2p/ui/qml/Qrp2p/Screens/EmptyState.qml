import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// No conversation yet: how to reach someone, and how they can reach you (UI_DESIGN §6.2).
Item {
    id: empty

    required property var workspace

    signal findNearby()
    signal enterAddress()

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(440, empty.width - Theme.s6 * 2)
        spacing: Theme.s4

        Icon {
            Layout.alignment: Qt.AlignHCenter
            name: "message-square"
            size: 40
            color: Theme.textSecondary
        }
        AppText {
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            text: empty.workspace.contactCount > 0 ? qsTr("Choose a conversation") : qsTr("No conversations yet")
            role: "title"
            Accessible.role: Accessible.Heading
        }
        AppText {
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            text: qsTr("QRP2P connects directly to people on your local network. Nothing is relayed through a server.")
            role: "secondary"
            wrapMode: Text.Wrap
        }
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: Theme.s2

            AppButton {
                kind: "primary"
                iconName: "radio"
                text: qsTr("Find people nearby")
                onClicked: empty.findNearby()
            }
            AppButton {
                text: qsTr("Enter an address")
                onClicked: empty.enterAddress()
            }
        }
        AppText {
            Layout.fillWidth: true
            Layout.topMargin: Theme.s2
            horizontalAlignment: Text.AlignHCenter
            visible: empty.workspace.addresses.length > 0
            text: qsTr("Others can reach you at %1:%2 · your ID %3")
                .arg(empty.workspace.addresses[0] || "").arg(empty.workspace.port).arg(empty.workspace.shortId)
            role: "small"
            wrapMode: Text.Wrap
        }
    }
}
