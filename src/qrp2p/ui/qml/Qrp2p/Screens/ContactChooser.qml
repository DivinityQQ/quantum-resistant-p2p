import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// All contacts (searchable) and, separately, people announced nearby. Nearby entries are
// unauthenticated hints: connecting proves who answers (UI_DESIGN §3.1, §6.2).
T.Popup {
    id: chooser

    required property var workspace

    signal enterAddress()

    function openContacts() {
        open()
        search.forceActiveFocus()
    }

    function openNearby() {
        open()
        Qt.callLater(() => flick.contentY = Math.max(0, nearbyHeading.y - Theme.s2))
    }

    width: Math.min(460, parent ? parent.width - Theme.s4 * 2 : 460)
    height: Math.min(implicitHeight, parent ? parent.height - y - Theme.s4 : 600)
    implicitHeight: content.implicitHeight + topPadding + bottomPadding
    padding: Theme.s3
    modal: true
    focus: true
    closePolicy: T.Popup.CloseOnEscape | T.Popup.CloseOnPressOutside

    onClosed: workspace.setSearch("")

    T.Overlay.modal: Rectangle {
        color: "transparent"
    }

    background: Rectangle {
        color: Theme.surface
        radius: Theme.radiusCard
        border.width: 1
        border.color: Theme.divider
    }

    contentItem: ColumnLayout {
        id: content
        spacing: Theme.s2

        AppTextField {
            id: search
            Layout.fillWidth: true
            placeholderText: qsTr("Search contacts by name or ID")
            onTextChanged: chooser.workspace.setSearch(text)
            onAccepted: {
                if (contacts.count > 0) {
                    chooser.workspace.select(contacts.model.get(0).contactId)
                    chooser.close()
                }
            }
            Keys.onDownPressed: if (contacts.count > 0) { contacts.currentIndex = 0; contacts.forceActiveFocus() }
        }

        Flickable {
            id: flick
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(lists.implicitHeight, 520)
            contentWidth: width
            contentHeight: lists.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            T.ScrollBar.vertical: AppScrollBar {}

            ColumnLayout {
                id: lists
                width: flick.width
                spacing: Theme.s1

                SectionHeading {
                    text: qsTr("Contacts")
                    visible: chooser.workspace.contactCount > 0
                    leftPadding: Theme.s2
                }
                AppText {
                    visible: chooser.workspace.contactCount > 0 && contacts.count === 0
                    Layout.fillWidth: true
                    leftPadding: Theme.s2
                    text: qsTr("No contact matches.")
                    role: "secondary"
                }
                ListView {
                    id: contacts
                    Layout.fillWidth: true
                    Layout.preferredHeight: contentHeight
                    interactive: false
                    model: chooser.workspace.contacts
                    keyNavigationEnabled: true
                    Keys.onReturnPressed: if (currentItem) currentItem.clicked()
                    Keys.onUpPressed: event => {
                        if (currentIndex === 0) search.forceActiveFocus()
                        else event.accepted = false
                    }
                    delegate: T.ItemDelegate {
                        id: entry
                        required property int index
                        required property string contactId
                        required property string name
                        required property string initial
                        required property string shortId
                        required property string trust
                        required property string presence
                        required property string presenceText
                        required property int unread
                        required property string description

                        width: ListView.view.width
                        implicitHeight: 52
                        leftPadding: Theme.s2
                        rightPadding: Theme.s2
                        hoverEnabled: true
                        highlighted: ListView.isCurrentItem && ListView.view.activeFocus
                        Accessible.name: description
                        onClicked: {
                            chooser.workspace.select(contactId)
                            chooser.close()
                        }

                        contentItem: RowLayout {
                            spacing: Theme.s3
                            Avatar {
                                initial: entry.initial
                                unread: entry.unread
                                size: 34
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 1
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.s2
                                    AppText {
                                        text: entry.name
                                        font.weight: Theme.weightMedium
                                        elide: Text.ElideRight
                                        Layout.maximumWidth: 200
                                    }
                                    TrustBadge {
                                        trust: entry.trust
                                    }
                                    Item {
                                        Layout.fillWidth: true
                                    }
                                }
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.s1 + 2
                                    PresenceDot {
                                        presence: entry.presence
                                    }
                                    AppText {
                                        text: entry.presenceText + "  ·  " + entry.shortId
                                        role: "small"
                                    }
                                    Item {
                                        Layout.fillWidth: true
                                    }
                                }
                            }
                        }
                        background: Rectangle {
                            radius: Theme.radiusControl
                            color: entry.down ? Theme.pressedFill
                                : entry.hovered || entry.highlighted ? Theme.hoverFill
                                : entry.contactId === chooser.workspace.selectedId ? Theme.surfaceSubtle : "transparent"
                        }
                    }
                }

                Divider {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.s2
                    Layout.bottomMargin: Theme.s1
                    visible: chooser.workspace.contactCount > 0
                }
                SectionHeading {
                    id: nearbyHeading
                    text: qsTr("Nearby on this network")
                    leftPadding: Theme.s2
                }
                AppText {
                    Layout.fillWidth: true
                    leftPadding: Theme.s2
                    rightPadding: Theme.s2
                    text: qsTr("Announced names are unverified hints. Connecting shows who really answers.")
                    role: "small"
                    wrapMode: Text.Wrap
                }
                AppText {
                    visible: chooser.workspace.nearby.count === 0
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.s2
                    leftPadding: Theme.s2
                    rightPadding: Theme.s2
                    text: chooser.workspace.discovery
                        ? qsTr("Nobody else is announcing QRP2P on this network right now.")
                        : qsTr("Discovery is unavailable on this network. You can still connect by address.")
                    role: "secondary"
                    wrapMode: Text.Wrap
                }
                Repeater {
                    model: chooser.workspace.nearby

                    RowLayout {
                        id: peer
                        required property string key
                        required property string label
                        required property string idHint
                        required property string addresses

                        Layout.fillWidth: true
                        Layout.leftMargin: Theme.s2
                        Layout.rightMargin: Theme.s1
                        spacing: Theme.s3

                        Icon {
                            name: "radio"
                            color: Theme.textSecondary
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 1
                            AppText {
                                Layout.fillWidth: true
                                text: peer.label
                                elide: Text.ElideRight
                            }
                            AppText {
                                Layout.fillWidth: true
                                text: qsTr("ID starts %1 · %2").arg(peer.idHint).arg(peer.addresses)
                                role: "small"
                                elide: Text.ElideRight
                            }
                        }
                        AppButton {
                            compact: true
                            text: qsTr("Connect")
                            busy: chooser.workspace.addressBusy
                            onClicked: chooser.workspace.connectNearby(peer.key)
                        }
                    }
                }
                Banner {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.s2
                    visible: chooser.workspace.addressBusy || chooser.workspace.addressError !== ""
                    busy: chooser.workspace.addressBusy
                    kind: chooser.workspace.addressError !== "" ? "danger" : "neutral"
                    text: chooser.workspace.addressError !== "" ? chooser.workspace.addressError
                        : chooser.workspace.addressStage === "waiting"
                            ? qsTr("Waiting for them to accept your request…") : qsTr("Connecting…")
                    dismissible: chooser.workspace.addressError !== ""
                    onDismissed: chooser.workspace.clearAddressError()
                }
            }
        }

        Divider {
            Layout.fillWidth: true
        }
        AppButton {
            Layout.fillWidth: true
            kind: "quiet"
            iconName: "globe"
            text: qsTr("Connect by address…")
            onClicked: {
                chooser.close()
                chooser.enterAddress()
            }
        }
    }

    Connections {
        target: chooser.workspace
        function onAddressConnected(contactId) {
            chooser.close()
        }
    }
}
