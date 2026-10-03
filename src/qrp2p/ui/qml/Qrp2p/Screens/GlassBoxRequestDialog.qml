import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// Before asking a pinned contact for a glass-box session: what both sides will be able to see
// and save, and what happens if they decline (UI_DESIGN §8, DESIGN §11.3). Cancel is the default.
AppDialog {
    id: dialog

    property var conversation: null
    readonly property string who: conversation ? Theme.isolate(conversation.name) : ""

    titleText: qsTr("Ask %1 for a glass-box session?").arg(who)
    iconName: "eye"
    iconColor: Theme.exposureText
    initialFocus: cancelButton

    AppText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: qsTr("A glass-box session shows how the protocol works. If %1 accepts, every key and message of this session is visible to both of you in the Inspector, and either of you can save it. Your identity's private keys are never shown.").arg(dialog.who)
    }
    AppText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: qsTr("%1 is asked once your identity is proven, and can decline: the session then opens as a normal one. A normal session never becomes glass-box later.").arg(dialog.who)
    }
    Banner {
        Layout.fillWidth: true
        kind: "exposure"
        iconName: "eye"
        text: qsTr("Send nothing private in it: treat everything in this session as public.")
    }

    actions: [
        AppButton {
            objectName: "askGlassBox"
            kind: "exposure"
            iconName: "eye"
            text: qsTr("Ask for glass-box")
            onClicked: {
                if (dialog.conversation)
                    dialog.conversation.connectGlassBox()
                dialog.close()
            }
        },
        AppButton {
            id: cancelButton
            objectName: "cancelGlassBox"
            kind: "quiet"
            text: qsTr("Cancel")
            onClicked: dialog.close()
        }
    ]
}
