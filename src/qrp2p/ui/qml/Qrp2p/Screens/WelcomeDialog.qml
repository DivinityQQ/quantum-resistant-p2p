import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// After the vault is created: the new identity, with its real sizes as expandable facts.
AppDialog {
    id: dialog

    required property var app
    required property var workspace

    property bool expanded: false

    titleText: qsTr("Your identity is ready")
    initialFocus: startButton
    iconName: "key-round"
    closePolicy: T.Popup.NoAutoClose

    Component.onCompleted: if (app.welcome) open()
    onClosed: app.dismissWelcome()

    Connections {
        target: dialog.app
        function onWelcomeChanged() {
            if (!dialog.app.welcome)
                dialog.close()
        }
    }

    AppText {
        Layout.fillWidth: true
        text: qsTr("This is your ID. People you talk to see it, and it never changes unless you start over.")
        wrapMode: Text.Wrap
    }
    AppText {
        Layout.alignment: Qt.AlignHCenter
        Layout.topMargin: Theme.s2
        Layout.bottomMargin: Theme.s2
        text: dialog.workspace.shortId
        role: "mono"
        font.pixelSize: Theme.sizeHeading
        font.letterSpacing: 2
    }
    AppButton {
        kind: "quiet"
        compact: true
        iconName: dialog.expanded ? "chevron-down" : "chevron-right"
        text: qsTr("Identity bundle: %1 bytes").arg(dialog.workspace.bundleBytes.toLocaleString(Qt.locale(), "f", 0))
        onClicked: dialog.expanded = !dialog.expanded
    }
    ColumnLayout {
        visible: dialog.expanded
        Layout.fillWidth: true
        Layout.leftMargin: Theme.s4
        spacing: Theme.s1

        Repeater {
            model: dialog.workspace.identityParts
            RowLayout {
                required property var modelData
                Layout.fillWidth: true
                AppText {
                    Layout.fillWidth: true
                    text: parent.modelData.name
                    role: "secondary"
                }
                AppText {
                    text: qsTr("%1 bytes").arg(parent.modelData.size.toLocaleString(Qt.locale(), "f", 0))
                    role: "mono"
                }
            }
        }
        AppText {
            Layout.fillWidth: true
            Layout.topMargin: Theme.s1
            text: qsTr("Plus a version byte. The private keys are 32-byte seeds, kept only in your encrypted vault and never shown.")
            role: "small"
            wrapMode: Text.Wrap
        }
    }
    AppText {
        Layout.fillWidth: true
        text: qsTr("Next: find someone nearby, or give them your address from “This device” at the top.")
        role: "secondary"
        wrapMode: Text.Wrap
    }

    actions: [
        AppButton {
            id: startButton
            kind: "primary"
            text: qsTr("Get started")
            onClicked: dialog.close()
        }
    ]
}
