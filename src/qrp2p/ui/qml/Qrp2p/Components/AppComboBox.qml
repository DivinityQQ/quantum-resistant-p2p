import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// A choice from a short list of {value, label} options. The shown value is always `current`
// from the view model, also when it is not one of the presets (a value saved elsewhere, say):
// then it appears as an extra entry, labelled by `formatValue`, rather than as the first preset.
// Changes are reported through `chosen(value)`.
T.ComboBox {
    id: control

    property string label: ""
    property var current
    property var options: []
    property var formatValue: value => String(value)

    readonly property bool _preset: options.some(o => o.value === current)

    signal chosen(var value)

    model: _preset || current === undefined || current === null
        ? options : options.concat([{ value: current, label: formatValue(current) }])

    implicitWidth: 220
    implicitHeight: Theme.controlHeight
    leftPadding: Theme.s3
    rightPadding: Theme.s3 + Theme.iconSize
    textRole: "label"
    valueRole: "value"
    // `count` makes the binding re-run once the model is populated; indexOfValue alone does not.
    currentIndex: count > 0 ? Math.max(0, indexOfValue(current)) : -1
    font.family: Theme.family
    font.pixelSize: Theme.sizeBody
    hoverEnabled: true
    focusPolicy: Qt.StrongFocus
    Accessible.name: label

    onActivated: index => {
        const value = valueAt(index)
        currentIndex = Qt.binding(() => control.count > 0 ? Math.max(0, indexOfValue(control.current)) : -1)
        if (value !== current)
            chosen(value)
    }

    delegate: T.ItemDelegate {
        required property var model
        required property int index

        width: ListView.view ? ListView.view.width : implicitWidth
        implicitHeight: Theme.controlHeight
        leftPadding: Theme.s3
        rightPadding: Theme.s3
        highlighted: control.highlightedIndex === index
        hoverEnabled: true
        contentItem: AppText {
            text: parent.model[control.textRole]
            verticalAlignment: Text.AlignVCenter
            color: Theme.text
            font.weight: control.currentIndex === parent.index ? Theme.weightMedium : Theme.weightRegular
        }
        background: Rectangle {
            radius: Theme.radiusTight + 2
            color: parent.highlighted || parent.hovered ? Theme.hoverFill : "transparent"
        }
    }

    indicator: Icon {
        x: control.width - width - Theme.s2
        anchors.verticalCenter: parent.verticalCenter
        name: "chevron-down"
        color: Theme.textSecondary
    }

    contentItem: AppText {
        text: control.displayText
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
        color: control.enabled ? Theme.text : Theme.textSecondary
    }

    background: Rectangle {
        radius: Theme.radiusControl
        color: !control.enabled ? Theme.surfaceSubtle : control.hovered ? Theme.hoverFill : Theme.surface
        border.width: control.activeFocus ? 2 : 1
        border.color: control.activeFocus ? Theme.focus : control.enabled ? Theme.controlBoundary : Theme.divider
    }

    popup: T.Popup {
        y: control.height + 4
        width: control.width
        implicitHeight: Math.min(list.contentHeight + topPadding + bottomPadding, 320)
        padding: Theme.s1

        contentItem: ListView {
            id: list
            clip: true
            implicitHeight: contentHeight
            model: control.delegateModel
            currentIndex: control.highlightedIndex
            T.ScrollBar.vertical: AppScrollBar {}
        }
        background: Rectangle {
            color: Theme.surface
            radius: Theme.radiusControl + 2
            border.width: 1
            border.color: Theme.divider
        }
    }
}
