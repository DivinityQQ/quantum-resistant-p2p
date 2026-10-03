import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// The top bar: product label, this device's network facts, the Inspector and the application
// menu (Connect, Contacts, Settings, Lock).
Item {
    id: bar

    required property var app
    required property var workspace
    property bool inspectorOpen: false

    signal openChooser()
    signal openConnect()
    signal openSettings()
    signal openShortcuts()
    signal toggleInspector()

    implicitHeight: 56

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Theme.s6
        anchors.rightMargin: Theme.s4
        spacing: Theme.s2

        AppText {
            text: "QRP2P"
            role: "title"
            font.letterSpacing: -0.2
            Accessible.role: Accessible.Heading
        }
        Item {
            Layout.fillWidth: true
        }
        AppButton {
            id: network
            kind: "quiet"
            compact: true
            iconName: bar.workspace.discovery ? "radio" : "network"
            text: bar.workspace.discovery ? qsTr("Local network") : qsTr("Discovery off")
            toolTipText: qsTr("This device: your ID and the addresses others can dial")
            onClicked: devicePopup.open()

            DevicePopup {
                id: devicePopup
                y: network.height + Theme.s1
                x: network.width - width
                app: bar.app
                workspace: bar.workspace
            }
        }
        Divider {
            vertical: true
            Layout.preferredHeight: 20
        }
        AppButton {
            objectName: "inspectorButton"
            kind: "quiet"
            compact: true
            iconName: bar.inspectorOpen ? "minimize-2" : "panel-right"
            text: bar.inspectorOpen ? qsTr("Close Inspector") : qsTr("Inspector")
            toolTipText: qsTr("Session Inspector: the protocol behind this conversation (Ctrl+I)")
            onClicked: bar.toggleInspector()
        }
        IconButton {
            id: menuButton
            label: qsTr("Menu")
            iconName: "ellipsis"
            active: menu.visible
            onClicked: menu.visible ? menu.close() : menu.open()

            AppMenu {
                id: menu
                y: menuButton.height + Theme.s1
                x: menuButton.width - width

                AppMenuItem {
                    text: qsTr("Connect to someone…")
                    iconName: "user-plus"
                    shortcutText: "Ctrl+N"
                    onTriggered: bar.openConnect()
                }
                AppMenuItem {
                    text: qsTr("All contacts")
                    iconName: "users"
                    shortcutText: "Ctrl+K"
                    onTriggered: bar.openChooser()
                }
                AppMenuSeparator {}
                AppMenuItem {
                    text: qsTr("Settings")
                    iconName: "settings"
                    shortcutText: "Ctrl+,"
                    onTriggered: bar.openSettings()
                }
                AppMenuItem {
                    text: qsTr("Keyboard shortcuts")
                    iconName: "keyboard"
                    onTriggered: bar.openShortcuts()
                }
                AppMenuSeparator {}
                AppMenuItem {
                    text: qsTr("Lock")
                    iconName: "lock"
                    shortcutText: "Ctrl+L"
                    onTriggered: bar.app.lock()
                }
            }
        }
    }
}
