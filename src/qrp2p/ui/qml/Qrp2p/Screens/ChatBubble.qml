import QtQuick
import Qrp2p.Theme
import Qrp2p.Components

// One chat message. Plain, selectable text; the sender is the session, shown by side and colour
// together with the conversation's name, never by anything inside the message (DESIGN §8.2).
Rectangle {
    id: bubble

    required property string text
    required property bool outgoing
    required property bool groupStart
    required property bool groupEnd
    property real maxWidth: 400

    readonly property int padH: Theme.s4 - 2
    readonly property int padV: Theme.s2 + 2
    readonly property int big: Theme.radiusBubble
    readonly property int small: 6

    implicitWidth: Math.min(maxWidth, Math.ceil(measure.implicitWidth) + padH * 2 + 1)
    implicitHeight: body.contentHeight + padV * 2
    color: outgoing ? Theme.primaryFill : Theme.surfaceSubtle
    // Within a group the sender's side tightens; the group's last bubble keeps a small tail.
    topLeftRadius: !outgoing && !groupStart ? small : big
    bottomLeftRadius: !outgoing ? small : big
    topRightRadius: outgoing && !groupStart ? small : big
    bottomRightRadius: outgoing ? small : big

    // The text's natural width (longest line), measured without wrapping.
    Text {
        id: measure
        visible: false
        text: bubble.text
        textFormat: Text.PlainText
        font: body.font
    }

    TextEdit {
        id: body
        objectName: "bubbleText"
        x: bubble.padH
        y: bubble.padV
        width: bubble.width - bubble.padH * 2
        text: bubble.text
        textFormat: TextEdit.PlainText
        readOnly: true
        selectByMouse: true
        persistentSelection: false
        wrapMode: TextEdit.Wrap
        color: bubble.outgoing ? Theme.primaryText : Theme.text
        selectionColor: bubble.outgoing ? Theme.primaryText : Theme.selectionFill
        selectedTextColor: bubble.outgoing ? Theme.primaryFill : Theme.selectionText
        font.family: Theme.family
        font.pixelSize: Theme.sizeBody
        activeFocusOnPress: true
        Accessible.role: Accessible.StaticText
        Accessible.name: (bubble.outgoing ? qsTr("You: ") : "") + bubble.text
    }
}
