import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// The selected frame's fields: name, body offset, size and a value where one can be read off
// the bytes. Up and Down move the selection, which highlights the field's bytes; a decrypted
// part's rows follow under their own heading (glass-box and lab sessions only).
ListView {
    id: table

    required property var inspector
    readonly property int offsetWidth: 96
    readonly property int sizeWidth: 88
    readonly property bool showValue: width >= 480

    objectName: "fieldTable"
    model: inspector.fields
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    activeFocusOnTab: true
    keyNavigationEnabled: false
    function selected() { return inspector.fields.indexOf(inspector.selectedField) }
    highlightMoveDuration: 0
    headerPositioning: ListView.OverlayHeader
    T.ScrollBar.vertical: AppScrollBar {
        id: bar
    }
    Accessible.role: Accessible.Table
    Accessible.name: qsTr("Message fields")

    function step(delta) {
        if (count === 0)
            return
        const next = Math.max(0, Math.min(count - 1, selected() + delta))
        inspector.selectField(inspector.fields.get(next).key)
        positionViewAtIndex(next, ListView.Contain)
    }
    Keys.onUpPressed: step(-1)
    Keys.onDownPressed: step(1)
    Keys.onPressed: event => {
        if (event.matches(StandardKey.Copy) && inspector.selectedField !== "") {
            inspector.copyField(inspector.selectedField)
            event.accepted = true
        }
    }

    FocusRing {
        visible: table.activeFocus
        anchors.margins: 0
    }

    header: Rectangle {
        width: table.width - bar.gutter
        height: Math.round(Theme.sizeSmall * 2.2)
        z: 2
        color: Theme.canvas

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.s3
            anchors.rightMargin: Theme.s3
            spacing: Theme.s2

            AppText {
                Layout.fillWidth: true
                text: qsTr("Field")
                role: "label"
            }
            AppText {
                Layout.preferredWidth: table.offsetWidth
                text: qsTr("Body offset")
                role: "label"
            }
            AppText {
                Layout.preferredWidth: table.sizeWidth
                text: qsTr("Size")
                role: "label"
            }
            AppText {
                Layout.preferredWidth: 140
                visible: table.showValue
                text: qsTr("Value")
                role: "label"
            }
        }
    }

    // A value without a byte range (a decoded MessagePack field, the record's nonce) shows a
    // dash, never a zero: zero would be an observed offset (UI_DESIGN §10).
    delegate: Column {
        id: line

        required property int index
        required property string key
        required property string name
        required property int depth
        required property string source
        required property int start
        required property int length
        required property int bodyOffset
        required property string value
        // The decrypted rows follow the frame's under their own heading.
        readonly property bool opensPlaintext: source === "plaintext"
            && (index === 0 || table.inspector.fields.get(index - 1).source !== "plaintext")

        width: table.width - bar.gutter

        RowLayout {
            width: parent.width
            height: visible ? implicitHeight + Theme.s3 : 0
            visible: line.opensPlaintext
            spacing: Theme.s2

            AppText {
                Layout.leftMargin: Theme.s3
                Layout.alignment: Qt.AlignBottom
                text: qsTr("Decrypted contents")
                role: "label"
                color: Theme.exposureText
            }
            AppText {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignBottom
                text: qsTr("offsets within the plaintext")
                role: "small"
                elide: Text.ElideRight
            }
        }

        T.ItemDelegate {
            id: entry

            readonly property string key: line.key
            readonly property string name: line.name
            readonly property int depth: line.depth
            readonly property string source: line.source
            readonly property int start: line.start
            readonly property int length: line.length
            readonly property int bodyOffset: line.bodyOffset
            readonly property string value: line.value
            readonly property bool ranged: length > 0 || source === "frame"
            readonly property bool selected: key === table.inspector.selectedField

            width: parent.width
            implicitHeight: Math.round(Theme.sizeBody * 1.9)
            leftPadding: Theme.s3 + depth * Theme.s4
            rightPadding: Theme.s3
            hoverEnabled: true
            focusPolicy: Qt.NoFocus
            Accessible.role: Accessible.Row
            Accessible.name: ranged ? qsTr("%1, %2, %n bytes", "", length).arg(name).arg(offsetText.text)
                : qsTr("%1, no byte range").arg(name)
            Accessible.selected: selected

            onClicked: {
                table.forceActiveFocus()
                table.inspector.selectField(key)
            }

            contentItem: RowLayout {
                spacing: Theme.s2

                AppText {
                    Layout.fillWidth: true
                    text: entry.name
                    elide: Text.ElideRight
                    role: entry.depth > 0 ? "secondary" : "body"
                    color: entry.selected ? Theme.selectionText : entry.depth > 0 ? Theme.textSecondary : Theme.text
                    font.weight: entry.selected ? Theme.weightMedium : Theme.weightRegular
                }
                AppText {
                    id: offsetText
                    Layout.preferredWidth: table.offsetWidth
                    text: !entry.ranged ? "—"
                        : entry.source === "plaintext" ? String(entry.start)
                        : entry.bodyOffset < 0 ? qsTr("header +%1").arg(entry.start)
                        : String(entry.bodyOffset)
                    role: "mono"
                    color: entry.selected ? Theme.selectionText : Theme.text
                }
                AppText {
                    Layout.preferredWidth: table.sizeWidth
                    text: entry.ranged ? entry.length + " B" : "—"
                    role: "mono"
                    color: entry.selected ? Theme.selectionText : Theme.text
                }
                AppText {
                    Layout.preferredWidth: 140
                    visible: table.showValue
                    text: entry.value
                    elide: Text.ElideRight
                    role: "small"
                    color: entry.selected ? Theme.selectionText : Theme.textSecondary
                }
            }
            background: Rectangle {
                radius: Theme.radiusTight + 2
                color: entry.selected ? Theme.selectionFill : entry.hovered ? Theme.hoverFill : "transparent"
            }
        }
    }
}
