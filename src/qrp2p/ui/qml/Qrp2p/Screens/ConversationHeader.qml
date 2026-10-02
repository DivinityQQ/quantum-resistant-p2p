import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// Who this is, whether they are verified, and whether a session is open: three separate facts
// (UI_DESIGN §1.3). The actions that matter now are buttons; the rest live in the menu.
Item {
    id: header

    required property var conversation

    signal verify()
    signal details()
    signal confirm(string action)

    // In a narrow pane the actions shrink to icons and badges to their shields.
    readonly property bool compact: width < 560

    implicitHeight: row.implicitHeight + Theme.s6

    RowLayout {
        id: row
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: Theme.s3

        Avatar {
            initial: header.conversation.avatarInitial
            size: 44
        }
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2

            RowLayout {
                spacing: Theme.s3
                Layout.fillWidth: true

                AppText {
                    text: header.conversation.name
                    role: "title"
                    elide: Text.ElideRight
                    Layout.maximumWidth: header.width * (header.compact ? 0.4 : 0.45)
                    Accessible.role: Accessible.Heading
                }
                TrustBadge {
                    trust: header.conversation.trust
                    compact: header.compact
                }
                Tag {
                    visible: header.conversation.glassBox
                    text: "GLASS-BOX"
                    kind: "exposure"
                    iconName: "eye"
                }
                Item {
                    Layout.fillWidth: true
                }
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.s1 + 2
                PresenceDot {
                    presence: header.conversation.presence
                }
                AppText {
                    role: "small"
                    text: header.conversation.online
                        ? qsTr("Online · %1").arg(header.conversation.sessionProfile)
                        : header.conversation.presenceText
                }
                AppText {
                    role: "small"
                    text: "·  " + header.conversation.shortId
                    font.family: Theme.monoFamily
                    visible: !header.compact
                }
                Item {
                    Layout.fillWidth: true
                }
            }
        }
        AppButton {
            visible: !header.conversation.online && header.conversation.trust !== "blocked"
            compact: header.compact
            text: header.conversation.presence === "connecting" || header.conversation.presence === "waiting"
                ? qsTr("Connecting…") : qsTr("Connect")
            busy: header.conversation.presence === "connecting" || header.conversation.presence === "waiting"
            iconName: "link-2"
            onClicked: header.conversation.connectSession()
        }
        AppButton {
            visible: header.conversation.trust === "pinned"
            kind: "quiet"
            iconName: "fingerprint"
            text: header.compact ? "" : qsTr("Verify")
            toolTipText: qsTr("Compare safety numbers with %1").arg(Theme.isolate(header.conversation.name))
            onClicked: header.verify()
        }
        IconButton {
            id: more
            label: qsTr("More actions for %1").arg(Theme.isolate(header.conversation.name))
            iconName: "ellipsis"
            active: menu.visible
            onClicked: menu.visible ? menu.close() : menu.open()

            AppMenu {
                id: menu
                y: more.height + Theme.s1
                x: more.width - width

                AppMenuItem {
                    text: qsTr("Contact details…")
                    iconName: "info"
                    onTriggered: header.details()
                }
                AppMenuItem {
                    text: qsTr("Safety number…")
                    iconName: "fingerprint"
                    onTriggered: header.verify()
                }
                AppMenuItem {
                    text: qsTr("Rekey now")
                    iconName: "refresh-cw"
                    enabled: header.conversation.online && header.conversation.initiator
                    onTriggered: header.conversation.rekey()
                }
                AppMenuItem {
                    text: qsTr("Disconnect")
                    iconName: "unplug"
                    enabled: header.conversation.online
                    onTriggered: header.conversation.disconnectSession()
                }
                AppMenuSeparator {}
                AppMenuItem {
                    text: qsTr("Delete history…")
                    iconName: "history"
                    danger: true
                    onTriggered: header.confirm("deleteHistory")
                }
                AppMenuItem {
                    text: header.conversation.trust === "blocked" ? qsTr("Unblock") : qsTr("Block…")
                    iconName: "ban"
                    danger: header.conversation.trust !== "blocked"
                    onTriggered: header.conversation.trust === "blocked"
                        ? header.conversation.unblock() : header.confirm("block")
                }
                AppMenuItem {
                    text: qsTr("Delete contact…")
                    iconName: "trash-2"
                    danger: true
                    onTriggered: header.confirm("deleteContact")
                }
            }
        }
    }
}
