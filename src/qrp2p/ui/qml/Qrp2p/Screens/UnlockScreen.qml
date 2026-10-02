import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// First run, unlock, and the states around them (UI_DESIGN §6.1): a calm form, busy activity
// without a fabricated percentage, and errors in words.
Item {
    id: screen

    required property var app

    readonly property string phase: app.phase
    readonly property bool working: app.busy || phase === "opening" || phase === "locking"

    Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: Math.max(height, column.implicitHeight + Theme.s8 * 2)
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: column
            width: Math.min(400, screen.width - Theme.s6 * 2)
            anchors.horizontalCenter: parent.horizontalCenter
            y: Math.max(Theme.s8, (screen.height - implicitHeight) / 2 - Theme.s6)
            spacing: Theme.s4

            Image {
                Layout.alignment: Qt.AlignLeft
                source: Qt.resolvedUrl("../../../resources/app-icon.svg")
                sourceSize.width: 44 * Screen.devicePixelRatio
                sourceSize.height: 44 * Screen.devicePixelRatio
                width: 44
                height: 44
                Layout.preferredWidth: 44
                Layout.preferredHeight: 44
                Accessible.ignored: true
            }

            Loader {
                Layout.fillWidth: true
                sourceComponent: screen.phase === "noVault" ? createForm
                    : screen.phase === "locked" || screen.phase === "opening" || screen.phase === "locking" ? unlockForm
                    : screen.phase === "inUse" ? inUse
                    : screen.phase === "failed" ? failed
                    : starting
            }
        }
    }

    Component {
        id: starting

        RowLayout {
            spacing: Theme.s3
            Spinner {}
            AppText {
                text: qsTr("Opening…")
                role: "secondary"
            }
        }
    }

    Component {
        id: createForm

        ColumnLayout {
            spacing: Theme.s4

            function submit() {
                screen.app.createVault(name.text, password.text, repeat.text)
            }

            AppText {
                text: qsTr("Create your vault")
                role: "heading"
                Accessible.role: Accessible.Heading
            }
            AppText {
                Layout.fillWidth: true
                text: qsTr("Your identity, contacts and messages stay on this device, encrypted under a password only you know. Nobody can recover it for you.")
                role: "secondary"
                wrapMode: Text.Wrap
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.s1
                AppTextField {
                    id: name
                    objectName: "createName"
                    Layout.fillWidth: true
                    placeholderText: qsTr("Your name (optional)")
                    maximumLength: 64
                    enabled: !screen.working
                    focus: true
                    KeyNavigation.tab: password
                    onAccepted: password.forceActiveFocus()
                }
                AppText {
                    Layout.fillWidth: true
                    text: qsTr("People nearby see it when they look for you. Names are hints; your ID is what counts.")
                    role: "small"
                    wrapMode: Text.Wrap
                }
            }
            PasswordField {
                id: password
                objectName: "createPassword"
                Layout.fillWidth: true
                placeholderText: qsTr("Password (at least 8 characters)")
                enabled: !screen.working
                KeyNavigation.tab: repeat
                onAccepted: repeat.forceActiveFocus()
            }
            PasswordField {
                id: repeat
                objectName: "createRepeat"
                Layout.fillWidth: true
                placeholderText: qsTr("Repeat the password")
                enabled: !screen.working
                invalid: repeat.length > 0 && repeat.text !== password.text && !repeat.activeFocus
                onAccepted: parent.submit()
            }
            AppText {
                Layout.fillWidth: true
                visible: screen.app.error !== ""
                text: screen.app.error
                color: Theme.dangerText
                wrapMode: Text.Wrap
                Accessible.role: Accessible.AlertMessage
            }
            AppButton {
                Layout.fillWidth: true
                kind: "primary"
                text: screen.working ? screen.app.busyText || qsTr("Creating…") : qsTr("Create vault")
                busy: screen.working
                onClicked: parent.submit()
            }
            AppText {
                Layout.fillWidth: true
                text: qsTr("Deriving the key takes about a second on purpose: it slows down anyone trying to guess your password.")
                role: "small"
                wrapMode: Text.Wrap
            }
        }
    }

    Component {
        id: unlockForm

        ColumnLayout {
            spacing: Theme.s4

            AppText {
                text: qsTr("Unlock QRP2P")
                role: "heading"
                Accessible.role: Accessible.Heading
            }
            Banner {
                Layout.fillWidth: true
                visible: screen.app.notice !== ""
                text: screen.app.notice
                kind: "neutral"
                dismissible: true
                onDismissed: screen.app.dismissNotice()
            }
            PasswordField {
                id: password
                objectName: "unlockPassword"
                Layout.fillWidth: true
                placeholderText: qsTr("Password")
                enabled: !screen.working
                focus: true
                onAccepted: screen.app.unlock(text)
                Component.onCompleted: forceActiveFocus()
            }
            AppText {
                Layout.fillWidth: true
                visible: screen.app.error !== ""
                text: screen.app.error
                color: Theme.dangerText
                wrapMode: Text.Wrap
                Accessible.role: Accessible.AlertMessage
            }
            AppButton {
                Layout.fillWidth: true
                kind: "primary"
                text: screen.phase === "locking" ? qsTr("Locking…")
                    : screen.working ? screen.app.busyText || qsTr("Unlocking…") : qsTr("Unlock")
                busy: screen.working
                enabled: password.length > 0 || screen.working
                onClicked: screen.app.unlock(password.text)
            }
            AppButton {
                Layout.fillWidth: true
                visible: screen.app.deviceUnlockAvailable && !screen.working
                kind: "quiet"
                iconName: "key-round"
                text: qsTr("Unlock with this device")
                onClicked: screen.app.unlockWithDevice()
            }
            AppText {
                Layout.fillWidth: true
                text: qsTr("Deriving the key takes about a second on purpose: it slows down anyone trying to guess your password.")
                role: "small"
                wrapMode: Text.Wrap
            }
        }
    }

    Component {
        id: inUse

        ColumnLayout {
            spacing: Theme.s3

            AppText {
                text: qsTr("QRP2P is already open")
                role: "heading"
            }
            AppText {
                Layout.fillWidth: true
                text: qsTr("Another QRP2P window is using this data folder. Switch to it, or close it and start QRP2P again.")
                role: "secondary"
                wrapMode: Text.Wrap
            }
            AppText {
                Layout.fillWidth: true
                text: screen.app.dataDir
                role: "mono"
                wrapMode: Text.WrapAnywhere
            }
        }
    }

    Component {
        id: failed

        ColumnLayout {
            spacing: Theme.s3

            AppText {
                text: qsTr("QRP2P could not start")
                role: "heading"
            }
            AppText {
                Layout.fillWidth: true
                text: screen.app.error
                color: Theme.dangerText
                wrapMode: Text.Wrap
            }
            AppText {
                Layout.fillWidth: true
                text: qsTr("Details are in app.log in the data folder:")
                role: "secondary"
                wrapMode: Text.Wrap
            }
            AppText {
                Layout.fillWidth: true
                text: screen.app.dataDir
                role: "mono"
                wrapMode: Text.WrapAnywhere
            }
        }
    }
}
