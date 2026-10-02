import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// A single-line input. Its boundary uses the control token, never a decorative divider, and
// focus thickens it in the focus colour (UI_DESIGN §4.2).
T.TextField {
    id: control

    property string label: placeholderText
    property bool invalid: false

    implicitWidth: 260
    implicitHeight: Theme.controlHeight
    leftPadding: Theme.s3
    rightPadding: Theme.s3
    verticalAlignment: TextInput.AlignVCenter
    font.family: Theme.family
    font.pixelSize: Theme.sizeBody
    color: Theme.text
    placeholderTextColor: Theme.textSecondary
    selectionColor: Theme.selectionFill
    selectedTextColor: Theme.selectionText
    selectByMouse: true
    persistentSelection: false
    Accessible.name: label

    AppText {
        x: control.leftPadding
        width: control.width - control.leftPadding - control.rightPadding
        anchors.verticalCenter: parent.verticalCenter
        text: control.placeholderText
        color: control.placeholderTextColor
        font: control.font
        elide: Text.ElideRight
        visible: control.length === 0 && control.preeditText === ""
    }

    background: Rectangle {
        radius: Theme.radiusControl
        color: control.enabled ? Theme.surface : Theme.surfaceSubtle
        border.width: control.activeFocus || control.invalid ? 2 : 1
        border.color: control.invalid ? Theme.dangerText
            : control.activeFocus ? Theme.focus
            : control.enabled ? Theme.controlBoundary : Theme.divider
    }
}
