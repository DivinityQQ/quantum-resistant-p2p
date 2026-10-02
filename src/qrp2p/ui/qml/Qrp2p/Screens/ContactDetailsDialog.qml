import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// A contact's identity, session and preferences. Changes to the profile apply to the next
// connection; they never alter an open session (UI_DESIGN §6.5).
AppDialog {
    id: dialog

    property var conversation

    signal verify()
    signal confirm(string action)

    readonly property var c: conversation

    titleText: c ? c.name : ""
    preferredWidth: 540

    onAboutToShow: if (c) nameField.text = c.name

    // Identity
    SectionHeading {
        text: qsTr("Identity")
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: Theme.s2
        AppTextField {
            id: nameField
            Layout.fillWidth: true
            label: qsTr("Name")
            maximumLength: 64
            onAccepted: if (dialog.c && text.trim() !== "") dialog.c.rename(text)
        }
        AppButton {
            text: qsTr("Rename")
            enabled: dialog.c !== null && nameField.text.trim() !== "" && nameField.text !== dialog.c.name
            onClicked: dialog.c.rename(nameField.text)
        }
    }
    AppText {
        Layout.fillWidth: true
        text: qsTr("Only you see this name. The peer's own announced name is just a hint.")
        role: "small"
        wrapMode: Text.Wrap
    }
    GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: Theme.s4
        rowSpacing: Theme.s2

        AppText { text: qsTr("ID"); role: "secondary" }
        AppText { text: dialog.c ? dialog.c.shortId : ""; role: "mono" }
        AppText { text: qsTr("Fingerprint"); role: "secondary"; Layout.alignment: Qt.AlignTop }
        AppText {
            Layout.fillWidth: true
            text: dialog.c ? dialog.c.fingerprint : ""
            role: "mono"
            color: Theme.textSecondary
            wrapMode: Text.Wrap
        }
        AppText { text: qsTr("Trust"); role: "secondary" }
        RowLayout {
            spacing: Theme.s3
            TrustBadge { trust: dialog.c ? dialog.c.trust : "pinned" }
            AppButton {
                visible: dialog.c && dialog.c.trust !== "blocked"
                kind: "quiet"
                compact: true
                text: dialog.c && dialog.c.trust === "verified" ? qsTr("Safety number") : qsTr("Verify…")
                onClicked: dialog.verify()
            }
        }
        AppText { text: qsTr("Last address"); role: "secondary"; visible: dialog.c && dialog.c.address !== "" }
        AppText { text: dialog.c ? dialog.c.address : ""; role: "mono"; visible: dialog.c && dialog.c.address !== "" }
    }

    // Session
    SectionHeading {
        text: qsTr("Session")
    }
    AppText {
        Layout.fillWidth: true
        visible: dialog.c && !dialog.c.online
        text: qsTr("Not connected.")
        role: "secondary"
    }
    GridLayout {
        Layout.fillWidth: true
        visible: dialog.c && dialog.c.online
        columns: 2
        columnSpacing: Theme.s4
        rowSpacing: Theme.s2

        AppText { text: qsTr("Profile"); role: "secondary" }
        AppText { text: dialog.c ? dialog.c.sessionProfile : "" }
        AppText { text: qsTr("Opened by"); role: "secondary" }
        AppText { text: dialog.c && dialog.c.initiator ? qsTr("You") : qsTr("Them") }
        AppText { text: qsTr("Exposure"); role: "secondary" }
        RowLayout {
            Tag {
                visible: dialog.c && dialog.c.glassBox
                text: "GLASS-BOX"
                kind: "exposure"
                iconName: "eye"
            }
            AppText {
                text: dialog.c && dialog.c.glassBox ? qsTr("Keys and messages visible to both of you")
                    : qsTr("Normal: secret values stay hidden")
                role: "small"
            }
        }
    }
    RowLayout {
        visible: dialog.c && dialog.c.online
        spacing: Theme.s2
        AppButton {
            compact: true
            iconName: "refresh-cw"
            text: qsTr("Rekey now")
            enabled: dialog.c && dialog.c.initiator
            toolTipText: dialog.c && dialog.c.initiator ? "" : qsTr("Only the side that opened the session starts a rekey.")
            onClicked: dialog.c.rekey()
        }
        AppButton {
            compact: true
            kind: "quiet"
            iconName: "unplug"
            text: qsTr("Disconnect")
            onClicked: dialog.c.disconnectSession()
        }
    }

    // Preferences
    SectionHeading {
        text: qsTr("Preferences")
    }
    GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: Theme.s4
        rowSpacing: Theme.s3

        AppText { text: qsTr("Profile"); role: "secondary" }
        AppComboBox {
            Layout.fillWidth: true
            label: qsTr("Profile")
            model: [{ value: "HYBRID-1", label: qsTr("HYBRID-1 (X-Wing, Ed25519 + ML-DSA-65)") },
                    { value: "PQ-CNSA-1", label: qsTr("PQ-CNSA-1 (ML-KEM-1024, ML-DSA-87)") }]
            current: dialog.c ? dialog.c.profile : "HYBRID-1"
            onChosen: value => dialog.c.setProfile(value)
        }
        Item { width: 1; height: 1 }
        AppText {
            Layout.fillWidth: true
            text: qsTr("Both of you must choose the same profile. It applies from the next connection.")
            role: "small"
            wrapMode: Text.Wrap
        }
        AppText { text: qsTr("Keep history"); role: "secondary" }
        AppComboBox {
            Layout.fillWidth: true
            label: qsTr("Keep history")
            model: [{ value: "forever", label: qsTr("Forever") },
                    { value: "30d", label: qsTr("30 days") },
                    { value: "session", label: qsTr("Until QRP2P locks") }]
            current: dialog.c ? dialog.c.retention : "forever"
            onChosen: value => dialog.c.setRetention(value)
        }
        AppText { text: qsTr("Files"); role: "secondary"; Layout.alignment: Qt.AlignTop; Layout.topMargin: Theme.s1 }
        ColumnLayout {
            Layout.fillWidth: true
            spacing: Theme.s2
            AppSwitch {
                Layout.fillWidth: true
                text: qsTr("Accept files automatically")
                description: dialog.c && dialog.c.trust === "verified"
                    ? qsTr("Up to the size below, without asking.")
                    : qsTr("Only for verified contacts.")
                enabled: dialog.c && dialog.c.trust === "verified"
                checked: dialog.c ? dialog.c.autoAcceptFiles : false
                onToggled: dialog.c.setAutoAccept(checked, limit.current)
            }
            AppComboBox {
                id: limit
                visible: dialog.c && dialog.c.autoAcceptFiles
                Layout.fillWidth: true
                label: qsTr("Largest file accepted automatically")
                model: [{ value: 10e6, label: "10 MB" }, { value: 100e6, label: "100 MB" },
                        { value: 1e9, label: "1 GB" }]
                current: dialog.c && dialog.c.autoAcceptLimit > 0 ? dialog.c.autoAcceptLimit : 100e6
                onChosen: value => dialog.c.setAutoAccept(true, value)
            }
        }
    }

    // Danger
    SectionHeading {
        text: qsTr("Delete or block")
    }
    Flow {
        Layout.fillWidth: true
        spacing: Theme.s2
        AppButton {
            kind: "danger"
            compact: true
            text: qsTr("Delete history…")
            onClicked: dialog.confirm("deleteHistory")
        }
        AppButton {
            kind: dialog.c && dialog.c.trust === "blocked" ? "secondary" : "danger"
            compact: true
            text: dialog.c && dialog.c.trust === "blocked" ? qsTr("Unblock") : qsTr("Block…")
            onClicked: dialog.c.trust === "blocked" ? dialog.c.unblock() : dialog.confirm("block")
        }
        AppButton {
            kind: "danger"
            compact: true
            text: qsTr("Delete contact…")
            onClicked: {
                dialog.close()
                dialog.confirm("deleteContact")
            }
        }
    }

    actions: [
        AppButton {
            kind: "primary"
            text: qsTr("Done")
            onClicked: dialog.close()
        }
    ]
}
