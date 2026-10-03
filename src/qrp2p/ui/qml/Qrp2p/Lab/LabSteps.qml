import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// The steps taken, in order. Selecting one offers to fork there: a new run that replays every
// step up to it, with the same randomness, and then continues live (DESIGN §11.6).
ColumnLayout {
    id: steps

    required property var lab
    property int chosen: -1             // the selected step's number

    spacing: Theme.s2

    RowLayout {
        Layout.fillWidth: true

        AppText {
            Layout.fillWidth: true
            text: qsTr("Steps (%1)").arg(steps.lab.stepCount)
            role: "label"
        }
        AppButton {
            objectName: "labFork"
            compact: true
            kind: "secondary"
            iconName: "git-fork"
            text: steps.chosen > 0 ? qsTr("Fork after step %1").arg(steps.chosen) : qsTr("Fork…")
            toolTipText: qsTr("Replay up to the selected step, then continue live from there")
            enabled: steps.chosen > 0 && steps.chosen <= steps.lab.stepCount && !steps.lab.busy
            onClicked: {
                steps.lab.fork(steps.chosen)
                steps.chosen = -1
            }
        }
    }

    ListView {
        id: list

        objectName: "labStepList"
        Layout.fillWidth: true
        Layout.preferredHeight: Math.min(contentHeight, 260)
        Layout.minimumHeight: Math.min(contentHeight, 120)
        model: steps.lab.steps
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        activeFocusOnTab: true
        keyNavigationEnabled: false
        T.ScrollBar.vertical: AppScrollBar {
            id: bar
        }
        Accessible.role: Accessible.List
        Accessible.name: qsTr("Lab steps")

        onCountChanged: Qt.callLater(positionViewAtEnd)
        Keys.onUpPressed: steps.chosen = Math.max(1, (steps.chosen > 0 ? steps.chosen : count + 1) - 1)
        Keys.onDownPressed: steps.chosen = Math.min(count, Math.max(steps.chosen, 0) + 1)

        FocusRing {
            visible: list.activeFocus
            anchors.margins: 0
            cornerRadius: Theme.radiusControl
        }

        delegate: T.ItemDelegate {
            id: entry

            required property int number
            required property var model
            readonly property string note: model.text
            readonly property bool selected: number === steps.chosen

            width: list.width - bar.gutter
            implicitHeight: line.implicitHeight + Theme.s1 * 2
            leftPadding: Theme.s2
            rightPadding: Theme.s2
            hoverEnabled: true
            focusPolicy: Qt.NoFocus
            Accessible.role: Accessible.ListItem
            Accessible.name: qsTr("Step %1: %2").arg(number).arg(note)
            Accessible.selected: selected

            onClicked: {
                list.forceActiveFocus()
                steps.chosen = selected ? -1 : number
            }

            contentItem: RowLayout {
                id: line
                spacing: Theme.s2

                AppText {
                    Layout.alignment: Qt.AlignTop
                    Layout.preferredWidth: 28
                    text: entry.number + "."
                    role: "small"
                    horizontalAlignment: Text.AlignRight
                    color: entry.selected ? Theme.selectionText : Theme.textSecondary
                }
                AppText {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignTop
                    text: entry.note
                    role: "small"
                    wrapMode: Text.Wrap
                    color: entry.selected ? Theme.selectionText : Theme.text
                }
            }
            background: Rectangle {
                radius: Theme.radiusTight + 2
                color: entry.selected ? Theme.selectionFill : entry.hovered ? Theme.hoverFill : "transparent"
            }
        }
    }
}
