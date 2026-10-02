import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Contact requests, glass-box requests and key mismatches (UI_DESIGN §6.2, §6.4, §8). The
// authenticated identity and the consequence come first; the answer shown afterwards is what the
// node reports, not what was clicked. A mismatch is never a dismissible toast, and Cancel is
// the safe default.
AppDialog {
    id: dialog

    required property var prompts

    readonly property string kind: prompts.kind
    readonly property string stage: prompts.stage
    readonly property bool asking: stage === "ask" || stage === "confirm"

    preferredWidth: 500
    closePolicy: T.Popup.NoAutoClose
    initialFocus: kind === "contact_request" && stage === "ask" ? nameField
        : kind === "mismatch" && stage === "ask" ? keepButton
        : kind === "mismatch" && stage === "confirm" ? backButton
        : null
    titleText: kind === "contact_request" ? qsTr("Contact request")
        : kind === "glass_box" ? qsTr("Glass-box session request")
        : kind === "mismatch" ? qsTr("%1's identity has changed").arg(Theme.isolate(prompts.name))
        : ""
    iconName: kind === "contact_request" ? "user-plus" : kind === "glass_box" ? "eye" : "shield-alert"
    iconColor: kind === "glass_box" ? Theme.exposureText : kind === "mismatch" ? Theme.dangerText : Theme.text

    function sync() {
        if (prompts.kind !== "" && !opened)
            open()
        else if (prompts.kind === "" && opened)
            close()
    }

    Connections {
        target: dialog.prompts
        function onChanged() {
            dialog.sync()
            if (dialog.visible)
                Qt.callLater(dialog.focusInitial)
        }
    }
    Component.onCompleted: sync()

    // -- contact request ---------------------------------------------------------------------
    AppText {
        Layout.fillWidth: true
        visible: dialog.kind === "contact_request" && dialog.asking
        text: qsTr("Someone on your network wants to add you. Their identity is authenticated, but you have never seen it before.")
        wrapMode: Text.Wrap
    }
    Rectangle {
        Layout.fillWidth: true
        visible: (dialog.kind === "contact_request" || dialog.kind === "glass_box") && dialog.asking
        implicitHeight: idColumn.implicitHeight + Theme.s3 * 2
        radius: Theme.radiusControl
        color: Theme.surfaceSubtle

        ColumnLayout {
            id: idColumn
            anchors.fill: parent
            anchors.margins: Theme.s3
            spacing: 2

            AppText {
                text: dialog.prompts.name !== "" ? dialog.prompts.name : qsTr("Unknown identity")
                font.weight: Theme.weightMedium
                elide: Text.ElideRight
                Layout.fillWidth: true
            }
            AppText {
                text: qsTr("ID %1 · %2").arg(dialog.prompts.shortId).arg(dialog.prompts.profile)
                role: "secondary"
            }
        }
    }
    AppText {
        Layout.fillWidth: true
        visible: dialog.kind === "contact_request" && dialog.asking
        text: qsTr("Accepting pins this identity, so its key can never silently change. To know who it is, compare safety numbers afterwards.")
        role: "secondary"
        wrapMode: Text.Wrap
    }
    AppTextField {
        id: nameField
        Layout.fillWidth: true
        visible: dialog.kind === "contact_request" && dialog.asking
        placeholderText: qsTr("Name this contact (only you see it)")
        maximumLength: 64
        onAccepted: dialog.prompts.accept(text)
    }
    Banner {
        Layout.fillWidth: true
        visible: dialog.kind === "contact_request" && dialog.asking && dialog.prompts.glassBoxRefused
        kind: "exposure"
        text: qsTr("They also asked for a glass-box session. That needs an existing contact, so this will be a normal session.")
    }

    // -- glass-box request -------------------------------------------------------------------
    AppText {
        Layout.fillWidth: true
        visible: dialog.kind === "glass_box" && dialog.asking
        text: qsTr("%1 asks for a glass-box session. All keys and messages of this session will be visible to both of you and can be saved.")
            .arg(Theme.isolate(dialog.prompts.name))
        wrapMode: Text.Wrap
    }
    AppText {
        Layout.fillWidth: true
        visible: dialog.kind === "glass_box" && dialog.asking
        text: qsTr("Identity private keys are never shown. If you choose a normal session, nothing secret is exposed.")
        role: "secondary"
        wrapMode: Text.Wrap
    }

    // -- key mismatch --------------------------------------------------------------------------
    AppText {
        Layout.fillWidth: true
        visible: dialog.kind === "mismatch" && dialog.stage === "ask"
        text: qsTr("You connected to %1, but a different identity answered. QRP2P stopped before revealing who you are.")
            .arg(Theme.isolate(dialog.prompts.name))
        wrapMode: Text.Wrap
    }
    GridLayout {
        Layout.fillWidth: true
        visible: dialog.kind === "mismatch" && dialog.stage === "ask"
        columns: 2
        columnSpacing: Theme.s3
        rowSpacing: Theme.s2

        AppText {
            text: qsTr("Saved")
            role: "secondary"
            Layout.alignment: Qt.AlignTop
        }
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            AppText {
                text: dialog.prompts.expectedShortId
                role: "mono"
                font.weight: Theme.weightMedium
            }
            AppText {
                Layout.fillWidth: true
                text: dialog.prompts.expectedFingerprint
                role: "mono"
                color: Theme.textSecondary
                wrapMode: Text.Wrap
            }
        }
        AppText {
            text: qsTr("Answered")
            role: "secondary"
            color: Theme.dangerText
            Layout.alignment: Qt.AlignTop
        }
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            AppText {
                text: dialog.prompts.actualShortId
                role: "mono"
                font.weight: Theme.weightMedium
                color: Theme.dangerText
            }
            AppText {
                Layout.fillWidth: true
                text: dialog.prompts.actualFingerprint
                role: "mono"
                color: Theme.dangerText
                wrapMode: Text.Wrap
            }
        }
    }
    AppText {
        Layout.fillWidth: true
        visible: dialog.kind === "mismatch" && dialog.stage === "ask"
        text: qsTr("This happens when %1 reinstalls QRP2P, or when someone on the network pretends to be them (a man in the middle). Ask %1 through another channel before you trust the new identity.")
            .arg(Theme.isolate(dialog.prompts.name))
        role: "secondary"
        wrapMode: Text.Wrap
    }
    ColumnLayout {
        Layout.fillWidth: true
        visible: dialog.kind === "mismatch" && dialog.stage === "confirm"
        spacing: Theme.s2

        AppText {
            Layout.fillWidth: true
            text: qsTr("Re-pin %1 to the identity %2?").arg(Theme.isolate(dialog.prompts.name)).arg(dialog.prompts.actualShortId)
            font.weight: Theme.weightMedium
            wrapMode: Text.Wrap
        }
        Repeater {
            model: [
                qsTr("%1 will be Not verified until you compare safety numbers again.").arg(Theme.isolate(dialog.prompts.name)),
                qsTr("Automatic file accepting turns off."),
                qsTr("A note in the conversation records the change.")
            ]
            RowLayout {
                required property string modelData
                Layout.fillWidth: true
                spacing: Theme.s2
                Icon {
                    name: "chevron-right"
                    color: Theme.textSecondary
                    size: Theme.iconSize - 4
                    Layout.alignment: Qt.AlignTop
                    Layout.topMargin: 2
                }
                AppText {
                    Layout.fillWidth: true
                    text: parent.modelData
                    role: "secondary"
                    wrapMode: Text.Wrap
                }
            }
        }
    }

    // -- shared ----------------------------------------------------------------------------------
    AppText {
        Layout.fillWidth: true
        visible: dialog.stage === "result"
        text: dialog.prompts.resultText
        color: dialog.prompts.resultIsError ? Theme.dangerText : Theme.text
        wrapMode: Text.Wrap
        Accessible.role: Accessible.AlertMessage
    }
    RowLayout {
        visible: dialog.stage === "working"
        spacing: Theme.s2
        Spinner {}
        AppText {
            text: qsTr("Answering…")
            role: "secondary"
        }
    }
    AppText {
        visible: (dialog.kind === "contact_request" || dialog.kind === "glass_box") && dialog.stage === "ask"
        text: dialog.prompts.secondsLeft > 0
            ? qsTr("Expires in %n s", "", dialog.prompts.secondsLeft) : qsTr("Expiring…")
        role: "small"
    }
    AppText {
        visible: dialog.prompts.queued > 0 && dialog.stage !== "working"
        text: qsTr("%n more waiting", "", dialog.prompts.queued)
        role: "small"
    }

    actions: [
        // Contact request
        AppButton {
            objectName: "acceptContact"
            visible: dialog.kind === "contact_request" && dialog.stage === "ask"
            kind: "primary"
            text: qsTr("Accept contact")
            enabled: dialog.prompts.secondsLeft > 0
            onClicked: dialog.prompts.accept(nameField.text)
        },
        AppButton {
            visible: dialog.kind === "contact_request" && dialog.stage === "ask"
            kind: "quiet"
            text: qsTr("Decline")
            onClicked: dialog.prompts.decline()
        },
        // Glass-box request
        AppButton {
            visible: dialog.kind === "glass_box" && dialog.stage === "ask"
            kind: "exposure"
            iconName: "eye"
            text: qsTr("Allow glass-box")
            enabled: dialog.prompts.secondsLeft > 0
            onClicked: dialog.prompts.accept("")
        },
        AppButton {
            visible: dialog.kind === "glass_box" && dialog.stage === "ask"
            text: qsTr("Normal session")
            onClicked: dialog.prompts.decline()
        },
        // Key mismatch
        AppButton {
            id: keepButton
            objectName: "keepIdentity"
            visible: dialog.kind === "mismatch" && dialog.stage === "ask"
            kind: "primary"
            text: qsTr("Cancel")
            onClicked: dialog.prompts.keep()
        },
        AppButton {
            objectName: "startRepin"
            visible: dialog.kind === "mismatch" && dialog.stage === "ask"
            kind: "danger"
            text: qsTr("Re-pin…")
            onClicked: dialog.prompts.startRepin()
        },
        AppButton {
            visible: dialog.kind === "mismatch" && dialog.stage === "confirm"
            kind: "danger"
            text: qsTr("Re-pin")
            onClicked: dialog.prompts.repin()
        },
        AppButton {
            id: backButton
            visible: dialog.kind === "mismatch" && dialog.stage === "confirm"
            kind: "quiet"
            text: qsTr("Back")
            onClicked: dialog.prompts.back()
        },
        AppButton {
            visible: dialog.kind === "mismatch" && dialog.stage === "result" && !dialog.prompts.resultIsError
            kind: "primary"
            iconName: "fingerprint"
            text: qsTr("Verify now")
            onClicked: dialog.prompts.verifyNow()
        },
        // Results
        AppButton {
            visible: dialog.stage === "result"
            kind: dialog.kind === "mismatch" && !dialog.prompts.resultIsError ? "quiet" : "primary"
            text: qsTr("Close")
            onClicked: dialog.prompts.close()
        }
    ]
}
