import QtQuick
import QtQuick.Layouts
import QtQuick.Dialogs
import Qrp2p.Theme
import Qrp2p.Components

// Settings, grouped as in UI_DESIGN §6.5. Each value shown is the one the vault holds; where a
// change applies later (next unlock, next connection), the screen says so. Lab-only algorithms
// never appear among the profiles.
AppDialog {
    id: dialog

    required property var app
    required property var workspace

    readonly property var s: workspace.settings

    titleText: qsTr("Settings")
    iconName: "settings"
    preferredWidth: 600

    onAboutToShow: {
        s.loadDeviceUnlock()
        s.clearError()
        displayName.text = s.displayName
        port.text = String(s.port)
        passwordForm.reset()
    }

    Banner {
        Layout.fillWidth: true
        visible: dialog.s.error !== ""
        kind: "danger"
        text: qsTr("Not saved: %1").arg(dialog.s.error)
        dismissible: true
        onDismissed: dialog.s.clearError()
    }

    // -- appearance --------------------------------------------------------------------------------
    SectionHeading {
        text: qsTr("Appearance")
    }
    GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: Theme.s4
        rowSpacing: Theme.s3

        AppText { text: qsTr("Theme"); role: "secondary" }
        SegmentedControl {
            label: qsTr("Theme")
            options: [{ value: "system", label: qsTr("System") }, { value: "light", label: qsTr("Light") },
                      { value: "dark", label: qsTr("Dark") }]
            current: dialog.s.appearance
            onChosen: value => dialog.s.set("appearance", value)
        }
        AppText { text: qsTr("Text size"); role: "secondary" }
        SegmentedControl {
            label: qsTr("Text size")
            options: dialog.s.textScales.map(v => ({ value: v, label: v + "%" }))
            current: dialog.s.textScale
            onChosen: value => dialog.s.set("text_scale", value)
        }
    }
    AppSwitch {
        Layout.fillWidth: true
        text: qsTr("Reduce motion")
        description: qsTr("Panels and dialogs change at once instead of animating.")
        checked: dialog.s.reducedMotion
        onToggled: dialog.s.set("reduced_motion", checked)
    }

    // -- identity and discovery ----------------------------------------------------------------------
    SectionHeading {
        text: qsTr("Identity and discovery")
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: Theme.s2
        AppTextField {
            id: displayName
            Layout.fillWidth: true
            label: qsTr("Display name")
            placeholderText: qsTr("Display name")
            maximumLength: 64
            onAccepted: dialog.s.set("display_name", text)
        }
        AppButton {
            text: qsTr("Save")
            enabled: displayName.text !== dialog.s.displayName
            onClicked: dialog.s.set("display_name", displayName.text)
        }
    }
    AppSwitch {
        Layout.fillWidth: true
        text: qsTr("Announce my name on the network")
        description: qsTr("Nearby people see your name next to your ID. Off: they see only the ID. Applies at the next unlock.")
        checked: dialog.s.announceName
        onToggled: dialog.s.set("announce_name", checked)
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: Theme.s2
        AppText {
            Layout.fillWidth: true
            text: qsTr("Listening port (applies at the next unlock; the next free one is used if busy)")
            role: "secondary"
            wrapMode: Text.Wrap
        }
        AppTextField {
            id: port
            Layout.preferredWidth: 96
            label: qsTr("Listening port")
            validator: IntValidator { bottom: 1; top: 65535 }
            inputMethodHints: Qt.ImhDigitsOnly
            onEditingFinished: if (acceptableInput && parseInt(text) !== dialog.s.port) dialog.s.set("port", parseInt(text))
        }
    }

    // -- connections ---------------------------------------------------------------------------------
    SectionHeading {
        text: qsTr("New contacts")
    }
    GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: Theme.s4
        rowSpacing: Theme.s3

        AppText { text: qsTr("Profile"); role: "secondary" }
        AppComboBox {
            Layout.fillWidth: true
            label: qsTr("Profile for new contacts")
            options: [{ value: "HYBRID-1", label: qsTr("HYBRID-1 (hybrid, default)") },
                    { value: "PQ-CNSA-1", label: qsTr("PQ-CNSA-1 (post-quantum only)") }]
            current: dialog.s.defaultProfile
            onChosen: value => dialog.s.set("default_profile", value)
        }
        AppText { text: qsTr("Keep history"); role: "secondary" }
        AppComboBox {
            Layout.fillWidth: true
            label: qsTr("Keep history of new contacts")
            options: [{ value: "forever", label: qsTr("Forever") }, { value: "30d", label: qsTr("30 days") },
                    { value: "session", label: qsTr("Until QRP2P locks") }]
            current: dialog.s.defaultRetention
            onChosen: value => dialog.s.set("default_retention", value)
        }
    }

    // -- locking -------------------------------------------------------------------------------------
    SectionHeading {
        text: qsTr("Locking")
    }
    GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: Theme.s4
        rowSpacing: Theme.s3

        AppText { text: qsTr("Lock when idle for"); role: "secondary" }
        AppComboBox {
            objectName: "autoLockCombo"
            Layout.fillWidth: true
            label: qsTr("Lock when idle for")
            options: [{ value: 5, label: qsTr("5 minutes") }, { value: 15, label: qsTr("15 minutes") },
                    { value: 30, label: qsTr("30 minutes") }, { value: 60, label: qsTr("1 hour") },
                    { value: 0, label: qsTr("Never") }]
            current: dialog.s.autoLockMinutes
            formatValue: value => value === 0 ? qsTr("Never") : qsTr("%n minutes", "", value)
            onChosen: value => dialog.s.set("auto_lock_minutes", value)
        }
    }
    AppSwitch {
        Layout.fillWidth: true
        text: qsTr("Remember on this device")
        description: dialog.s.deviceUnlockKnown
            ? qsTr("Unlock with the operating system's keychain instead of typing the password. Anyone who can use your account on this computer can then open QRP2P.")
            : qsTr("Checking the keychain…")
        enabled: dialog.s.deviceUnlockKnown && dialog.s.saving !== "device_unlock"
        checked: dialog.s.deviceUnlock
        onToggled: dialog.s.setDeviceUnlock(checked)
    }

    // -- files ---------------------------------------------------------------------------------------
    SectionHeading {
        text: qsTr("Files")
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: Theme.s2
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            AppText { text: qsTr("Save received files in"); role: "secondary" }
            AppText {
                Layout.fillWidth: true
                text: dialog.s.downloadsDir
                role: "mono"
                elide: Text.ElideMiddle
            }
        }
        AppButton {
            compact: true
            text: qsTr("Change…")
            onClicked: folderDialog.open()
        }
        AppButton {
            compact: true
            kind: "quiet"
            visible: dialog.s.downloadsCustom
            text: qsTr("Use default")
            onClicked: dialog.s.resetDownloadsFolder()
        }
    }
    GridLayout {
        Layout.fillWidth: true
        columns: 2
        columnSpacing: Theme.s4

        AppText { text: qsTr("Largest file accepted"); role: "secondary" }
        AppComboBox {
            objectName: "maxFileCombo"
            Layout.fillWidth: true
            label: qsTr("Largest file accepted")
            options: [{ value: 100e6, label: "100 MB" }, { value: 1e9, label: "1 GB" },
                    { value: 4294967296, label: "4 GiB" }, { value: 17179869184, label: "16 GiB" }]
            current: dialog.s.maxFileSize
            formatValue: value => Theme.formatBytes(value)
            onChosen: value => dialog.s.set("max_file_size", value)
        }
    }

    // -- security ------------------------------------------------------------------------------------
    SectionHeading {
        text: qsTr("Password")
    }
    ColumnLayout {
        id: passwordForm
        Layout.fillWidth: true
        spacing: Theme.s2

        property bool open: false
        property bool working: false
        property string result: ""
        property bool resultOk: false

        function reset() {
            open = false
            working = false
            result = ""
            oldPassword.clear()
            newPassword.clear()
            repeatPassword.clear()
        }

        AppButton {
            visible: !passwordForm.open
            text: qsTr("Change password…")
            iconName: "key-round"
            onClicked: {
                passwordForm.open = true
                oldPassword.forceActiveFocus()
            }
        }
        PasswordField {
            id: oldPassword
            visible: passwordForm.open
            Layout.fillWidth: true
            placeholderText: qsTr("Current password")
            enabled: !passwordForm.working
        }
        PasswordField {
            id: newPassword
            visible: passwordForm.open
            Layout.fillWidth: true
            placeholderText: qsTr("New password (at least 8 characters)")
            enabled: !passwordForm.working
        }
        PasswordField {
            id: repeatPassword
            visible: passwordForm.open
            Layout.fillWidth: true
            placeholderText: qsTr("Repeat the new password")
            enabled: !passwordForm.working
        }
        AppText {
            visible: passwordForm.open
            Layout.fillWidth: true
            text: qsTr("Everything is re-encrypted under new keys; this takes a few seconds. Backups made earlier stay readable with the old password.")
            role: "small"
            wrapMode: Text.Wrap
        }
        AppText {
            visible: passwordForm.result !== ""
            Layout.fillWidth: true
            text: passwordForm.result
            color: passwordForm.resultOk ? Theme.success : Theme.dangerText
            wrapMode: Text.Wrap
        }
        RowLayout {
            visible: passwordForm.open
            spacing: Theme.s2
            AppButton {
                kind: "primary"
                text: qsTr("Change password")
                busy: passwordForm.working
                enabled: oldPassword.length > 0 && newPassword.length > 0
                onClicked: {
                    passwordForm.working = true
                    passwordForm.result = ""
                    dialog.app.changePassword(oldPassword.text, newPassword.text, repeatPassword.text)
                }
            }
            AppButton {
                kind: "quiet"
                text: qsTr("Cancel")
                enabled: !passwordForm.working
                onClicked: passwordForm.reset()
            }
        }
        Connections {
            target: dialog.app
            function onPasswordChangeFinished(ok, text) {
                passwordForm.working = false
                passwordForm.result = text
                passwordForm.resultOk = ok
                if (ok) {
                    passwordForm.open = false
                    oldPassword.clear()
                    newPassword.clear()
                    repeatPassword.clear()
                }
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

    FolderDialog {
        id: folderDialog
        title: qsTr("Save received files in")
        onAccepted: dialog.s.setDownloadsFolder(selectedFolder.toString())
    }
}
