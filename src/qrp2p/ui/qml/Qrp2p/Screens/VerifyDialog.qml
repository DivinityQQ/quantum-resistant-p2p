import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// Safety-number comparison (DESIGN §5.2, UI_DESIGN §6.4): all 60 digits in 12 groups of five.
// "Mark as verified" is the user's statement that the numbers matched out of band.
AppDialog {
    id: dialog

    required property var workspace
    property var conversation

    readonly property var groups: conversation ? conversation.safetyNumber : []

    titleText: conversation ? qsTr("Verify %1").arg(Theme.isolate(conversation.name)) : ""
    iconName: "fingerprint"
    preferredWidth: 520

    onAboutToShow: if (conversation) conversation.loadSafetyNumber()

    AppText {
        Layout.fillWidth: true
        text: qsTr("Compare these numbers with %1 in person or on a call you trust. They are the same on both devices only if nobody is in the middle.")
            .arg(Theme.isolate(dialog.conversation ? dialog.conversation.name : ""))
        wrapMode: Text.Wrap
    }
    Rectangle {
        Layout.fillWidth: true
        implicitHeight: grid.implicitHeight + Theme.s4 * 2
        radius: Theme.radiusControl
        color: Theme.surfaceSubtle
        Accessible.role: Accessible.StaticText
        Accessible.name: qsTr("Safety number: %1").arg(dialog.groups.join(" "))

        GridLayout {
            id: grid
            anchors.centerIn: parent
            columns: dialog.width < 440 ? 3 : 4
            columnSpacing: Theme.s6
            rowSpacing: Theme.s3

            Repeater {
                model: dialog.groups
                AppText {
                    required property string modelData
                    text: modelData
                    role: "mono"
                    font.pixelSize: Math.round(Theme.sizeTitle * 1.05)
                    font.letterSpacing: 1
                    horizontalAlignment: Text.AlignHCenter
                }
            }
        }
        Spinner {
            anchors.centerIn: parent
            visible: dialog.groups.length === 0
        }
    }
    AppText {
        Layout.fillWidth: true
        text: dialog.conversation
            ? qsTr("Your ID %1 · %2's ID %3").arg(dialog.workspace.shortId)
                .arg(Theme.isolate(dialog.conversation.name)).arg(dialog.conversation.shortId)
            : ""
        role: "small"
        wrapMode: Text.Wrap
    }
    RowLayout {
        visible: dialog.conversation && dialog.conversation.trust === "verified"
        spacing: Theme.s2
        TrustBadge {
            trust: "verified"
        }
        AppText {
            text: qsTr("You marked this contact as verified.")
            role: "small"
        }
    }

    actions: [
        AppButton {
            visible: dialog.conversation && dialog.conversation.trust === "pinned"
            kind: "primary"
            iconName: "shield-check"
            text: qsTr("They match: mark as verified")
            enabled: dialog.groups.length > 0
            onClicked: {
                dialog.conversation.markVerified()
                dialog.close()
            }
        },
        AppButton {
            visible: dialog.conversation && dialog.conversation.trust === "verified"
            kind: "quiet"
            text: qsTr("Remove verification")
            onClicked: dialog.conversation.unverify()
        },
        AppButton {
            kind: dialog.conversation && dialog.conversation.trust === "verified" ? "primary" : "quiet"
            text: dialog.conversation && dialog.conversation.trust === "verified" ? qsTr("Close") : qsTr("Not now")
            onClicked: dialog.close()
        }
    ]
}
