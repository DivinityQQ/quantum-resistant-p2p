import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Connect by address: always available, also where discovery is blocked (DESIGN §6.2). Shows the
// real stages: connecting, then waiting for the other person to accept.
AppDialog {
    id: dialog

    required property var workspace

    titleText: qsTr("Connect by address")
    iconName: "globe"
    closePolicy: workspace.addressBusy ? T.Popup.NoAutoClose : T.Popup.CloseOnEscape

    initialFocus: host
    onAboutToShow: workspace.clearAddressError()

    function submit() {
        workspace.connectAddress(host.text, parseInt(port.text) || 0, name.text, profile.current)
    }

    AppText {
        Layout.fillWidth: true
        text: qsTr("Ask the other person for the address shown under “This device” in their QRP2P.")
        role: "secondary"
        wrapMode: Text.Wrap
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: Theme.s2

        AppTextField {
            id: host
            objectName: "connectHost"
            Layout.fillWidth: true
            placeholderText: qsTr("Address, e.g. 192.168.1.20")
            label: qsTr("Address")
            enabled: !dialog.workspace.addressBusy
            inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
            onAccepted: dialog.submit()
        }
        AppTextField {
            id: port
            Layout.preferredWidth: 96
            text: "47470"
            label: qsTr("Port")
            enabled: !dialog.workspace.addressBusy
            validator: IntValidator { bottom: 1; top: 65535 }
            inputMethodHints: Qt.ImhDigitsOnly
            onAccepted: dialog.submit()
        }
    }
    AppTextField {
        id: name
        Layout.fillWidth: true
        placeholderText: qsTr("Name to show for them (optional)")
        maximumLength: 64
        enabled: !dialog.workspace.addressBusy
        onAccepted: dialog.submit()
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: Theme.s3

        AppText {
            text: qsTr("Profile")
            role: "secondary"
        }
        AppComboBox {
            id: profile
            label: qsTr("Profile")
            enabled: !dialog.workspace.addressBusy
            options: [
                { value: "", label: qsTr("Default (%1)").arg(dialog.workspace.settings.defaultProfile) },
                { value: "HYBRID-1", label: "HYBRID-1" },
                { value: "PQ-CNSA-1", label: "PQ-CNSA-1" }
            ]
            current: ""
            onChosen: value => current = value
        }
    }
    Banner {
        Layout.fillWidth: true
        visible: dialog.workspace.addressBusy || dialog.workspace.addressError !== ""
        busy: dialog.workspace.addressBusy
        kind: dialog.workspace.addressError !== "" ? "danger" : "neutral"
        text: dialog.workspace.addressError !== "" ? dialog.workspace.addressError
            : dialog.workspace.addressStage === "waiting"
                ? qsTr("Waiting for them to accept your request (they have up to a minute)…")
                : qsTr("Connecting…")
    }

    actions: [
        AppButton {
            objectName: "connectButton"
            kind: "primary"
            text: qsTr("Connect")
            busy: dialog.workspace.addressBusy
            enabled: host.text.trim() !== "" && port.acceptableInput
            onClicked: dialog.submit()
        },
        AppButton {
            kind: "quiet"
            text: dialog.workspace.addressBusy ? qsTr("Hide") : qsTr("Cancel")
            onClicked: dialog.close()
        }
    ]

    Connections {
        target: dialog.workspace
        function onAddressConnected(contactId) {
            dialog.close()
        }
    }
}
