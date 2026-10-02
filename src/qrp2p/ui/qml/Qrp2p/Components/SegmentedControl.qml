import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// A small set of exclusive options shown at once (System/Light/Dark). Arrow keys move the
// choice; the shown choice follows `current` from the view model.
Rectangle {
    id: control

    property var options: []        // [{ value, label }]
    property var current
    property string label: ""

    signal chosen(var value)

    implicitWidth: row.implicitWidth + 4
    implicitHeight: Theme.controlHeight
    radius: Theme.radiusControl
    color: Theme.surfaceSubtle
    border.width: 1
    border.color: Theme.divider
    Accessible.role: Accessible.Grouping
    Accessible.name: label

    Row {
        id: row
        anchors.centerIn: parent
        spacing: 2

        Repeater {
            model: control.options

            T.Button {
                id: segment

                required property var modelData
                required property int index
                readonly property bool selected: modelData.value === control.current

                implicitHeight: control.height - 4
                implicitWidth: Math.max(64, label.implicitWidth + Theme.s4 * 2)
                hoverEnabled: true
                focusPolicy: Qt.StrongFocus
                checkable: false
                Accessible.role: Accessible.RadioButton
                Accessible.name: modelData.label
                Accessible.checked: selected
                Accessible.checkable: true

                onClicked: if (!selected) control.chosen(modelData.value)
                Keys.onLeftPressed: control.step(-1)
                Keys.onRightPressed: control.step(1)

                contentItem: AppText {
                    id: label
                    text: segment.modelData.label
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.weight: segment.selected ? Theme.weightMedium : Theme.weightRegular
                    color: segment.selected ? Theme.text : Theme.textSecondary
                }
                background: Rectangle {
                    radius: Theme.radiusControl - 2
                    color: segment.selected ? Theme.surface
                        : segment.hovered ? Theme.hoverFill : "transparent"
                    border.width: segment.selected ? 1 : 0
                    border.color: Theme.divider

                    FocusRing {
                        visible: segment.visualFocus
                        cornerRadius: parent.radius
                    }
                }
            }
        }
    }

    function step(delta) {
        let index = -1
        for (let i = 0; i < options.length; ++i)
            if (options[i].value === current)
                index = i
        const next = Math.max(0, Math.min(options.length - 1, index + delta))
        if (next !== index)
            chosen(options[next].value)
    }
}
