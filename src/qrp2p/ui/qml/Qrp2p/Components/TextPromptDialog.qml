import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme

// Asks for one line of text (a recording's title, say), prefilled and selected, so Enter takes
// the suggestion and typing replaces it. Cancel is always there; nothing happens until accepted.
AppDialog {
    id: dialog

    property string message: ""
    property string fieldLabel: ""
    property string acceptText: qsTr("Save")
    property string suggestion: ""
    property int maximumLength: 200

    signal submitted(string text)

    initialFocus: field

    function ask(suggested) {
        suggestion = suggested
        field.text = suggested
        open()
        field.selectAll()
    }

    function submit() {
        const text = field.text.trim()
        if (text === "")
            return
        dialog.submitted(text)
        dialog.close()
    }

    AppText {
        Layout.fillWidth: true
        visible: dialog.message !== ""
        text: dialog.message
        wrapMode: Text.Wrap
    }
    AppTextField {
        id: field
        objectName: "promptField"
        Layout.fillWidth: true
        label: dialog.fieldLabel
        maximumLength: dialog.maximumLength
        onAccepted: dialog.submit()
    }

    actions: [
        AppButton {
            objectName: "promptAccept"
            kind: "primary"
            text: dialog.acceptText
            enabled: field.text.trim() !== ""
            onClicked: dialog.submit()
        },
        AppButton {
            kind: "quiet"
            text: qsTr("Cancel")
            onClicked: dialog.close()
        }
    ]
}
