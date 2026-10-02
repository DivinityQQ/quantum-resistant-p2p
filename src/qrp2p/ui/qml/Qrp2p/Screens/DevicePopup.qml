import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// This device: the ID others see, and where they can reach it (for connecting by address).
T.Popup {
    id: popup

    required property var app
    required property var workspace

    width: 340
    implicitHeight: content.implicitHeight + topPadding + bottomPadding
    padding: Theme.s4
    modal: false
    focus: true
    closePolicy: T.Popup.CloseOnEscape | T.Popup.CloseOnPressOutsideParent

    onOpened: workspace.refreshNetwork()

    background: Rectangle {
        color: Theme.surface
        radius: Theme.radiusCard
        border.width: 1
        border.color: Theme.divider
    }

    contentItem: ColumnLayout {
        id: content
        spacing: Theme.s3

        AppText {
            text: qsTr("This device")
            role: "label"
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.s3

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                AppText {
                    text: popup.workspace.settings.displayName || qsTr("No display name")
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                }
                AppText {
                    text: qsTr("Your ID %1").arg(popup.workspace.shortId)
                    role: "secondary"
                }
            }
            AppButton {
                kind: "quiet"
                compact: true
                iconName: "copy"
                text: qsTr("Copy ID")
                onClicked: popup.app.copyText(popup.workspace.shortId)
            }
        }
        Divider {
            Layout.fillWidth: true
        }
        AppText {
            text: qsTr("Others can connect to")
            role: "label"
        }
        Repeater {
            model: popup.workspace.addresses

            RowLayout {
                required property string modelData
                readonly property string target: modelData.indexOf(":") >= 0
                    ? "[" + modelData + "]:" + popup.workspace.port
                    : modelData + ":" + popup.workspace.port

                Layout.fillWidth: true
                spacing: Theme.s2

                AppText {
                    Layout.fillWidth: true
                    text: parent.target
                    role: "mono"
                    elide: Text.ElideMiddle
                }
                IconButton {
                    label: qsTr("Copy %1").arg(parent.target)
                    iconName: "copy"
                    iconColor: Theme.textSecondary
                    onClicked: popup.app.copyText(parent.target)
                }
            }
        }
        AppText {
            visible: popup.workspace.addresses.length === 0
            Layout.fillWidth: true
            text: qsTr("No network address found. Connect this device to a network first.")
            role: "secondary"
            wrapMode: Text.Wrap
        }
        AppText {
            Layout.fillWidth: true
            text: popup.workspace.discovery
                ? qsTr("Announced on this network, so nearby people can find you.")
                : qsTr("Discovery is unavailable here; others can still connect by address.")
            role: "small"
            wrapMode: Text.Wrap
        }
    }
}
