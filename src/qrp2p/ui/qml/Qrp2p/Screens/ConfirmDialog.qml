import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// Confirmation for destructive actions, naming exactly what is lost.
AppDialog {
    id: dialog

    property string action: ""
    property var conversation: null

    function ask(what, target) {
        action = what
        conversation = target
        open()
    }

    readonly property string who: conversation ? Theme.isolate(conversation.name) : ""

    titleText: action === "deleteHistory" ? qsTr("Delete the history with %1?").arg(who)
        : action === "block" ? qsTr("Block %1?").arg(who)
        : action === "deleteContact" ? qsTr("Delete %1?").arg(who) : ""
    iconName: action === "block" ? "ban" : "trash-2"
    initialFocus: cancelButton  // the safe choice
    iconColor: Theme.dangerText

    AppText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: dialog.action === "deleteHistory"
            ? qsTr("Messages and file records with %1 are deleted from this device, and their key is destroyed. Backups made earlier stay readable with the password of that time.").arg(dialog.who)
            : dialog.action === "block"
            ? qsTr("An open session closes, and %1 can no longer connect to you. You can unblock them later.").arg(dialog.who)
            : qsTr("The contact, its pinned identity and the whole history are deleted from this device. If they connect again, they appear as a new contact request.")
    }

    actions: [
        AppButton {
            kind: "danger"
            text: dialog.action === "deleteHistory" ? qsTr("Delete history")
                : dialog.action === "block" ? qsTr("Block") : qsTr("Delete contact")
            onClicked: {
                if (dialog.conversation) {
                    if (dialog.action === "deleteHistory")
                        dialog.conversation.deleteHistory()
                    else if (dialog.action === "block")
                        dialog.conversation.block()
                    else if (dialog.action === "deleteContact")
                        dialog.conversation.deleteContact()
                }
                dialog.close()
            }
        },
        AppButton {
            id: cancelButton
            kind: "quiet"
            text: qsTr("Cancel")
            onClicked: dialog.close()
        }
    ]
}
