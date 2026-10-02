import QtQuick
import Qrp2p.Theme

// A password input: masked, with an explicit show/hide toggle. Never logged or kept by QML.
AppTextField {
    id: control

    property bool revealed: false

    echoMode: revealed ? TextInput.Normal : TextInput.Password
    passwordCharacter: "•"
    rightPadding: toggle.width + Theme.s1
    inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase

    IconButton {
        id: toggle
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        width: Theme.controlHeight - 4
        height: Theme.controlHeight - 4
        label: control.revealed ? qsTr("Hide password") : qsTr("Show password")
        iconName: control.revealed ? "eye-off" : "eye"
        iconColor: Theme.textSecondary
        focusPolicy: Qt.NoFocus
        onClicked: control.revealed = !control.revealed
    }
}
