import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Messages: every captured frame, and the selected one's fields and bytes as transmitted.
Item {
    id: view

    required property var inspector
    readonly property bool wide: width >= 860 * Math.max(1, Theme.scale)

    GridLayout {
        anchors.fill: parent
        columns: view.wide ? 3 : 1
        rowSpacing: 0
        columnSpacing: 0

        ListView {
            id: list

            objectName: "frameList"
            Layout.preferredWidth: view.wide ? Math.max(280, Math.round(view.width * 0.3)) : -1
            Layout.fillWidth: !view.wide
            Layout.fillHeight: view.wide
            Layout.preferredHeight: view.wide ? -1 : Math.round(view.height * 0.32)
            model: view.inspector.frames
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            keyNavigationEnabled: false
            activeFocusOnTab: true
            reuseItems: true
            // The selected frame's row, looked up when needed: never a binding on the view.
            function selected() { return view.inspector.frames.indexOf(String(view.inspector.selectedFrame)) }
            highlightMoveDuration: 0
            T.ScrollBar.vertical: AppScrollBar {
                id: bar
            }
            Accessible.role: Accessible.List
            Accessible.name: qsTr("Captured frames")

            function step(delta) {
                if (count === 0)
                    return
                const current = selected()
        const from = current < 0 ? (delta > 0 ? -1 : count) : current
                const next = Math.max(0, Math.min(count - 1, from + delta))
                view.inspector.selectFrame(view.inspector.frames.get(next).ordinal)
                positionViewAtIndex(next, ListView.Contain)
            }
            // A newly selected frame comes into view.
            property int shown: -1
            Connections {
                target: view.inspector
                function onSelectionChanged() {
                    if (view.inspector.selectedFrame === list.shown)
                        return
                    list.shown = view.inspector.selectedFrame
                    const index = list.selected()
                    if (index >= 0)
                        list.positionViewAtIndex(index, ListView.Contain)
                }
            }
            Keys.onUpPressed: step(-1)
            Keys.onDownPressed: step(1)
            Component.onCompleted: if (selected() >= 0) positionViewAtIndex(selected(), ListView.Center)

            FocusRing {
                visible: list.activeFocus
                anchors.margins: 0
                cornerRadius: 0
            }

            delegate: T.ItemDelegate {
                id: entry

                required property int ordinal
                required property string time
                required property string direction
                required property string name
                required property string size
                readonly property bool selected: ordinal === view.inspector.selectedFrame

                width: list.width - bar.gutter
                implicitHeight: lines.implicitHeight + Theme.s2 * 2
                leftPadding: Theme.s3
                rightPadding: Theme.s3
                hoverEnabled: true
                focusPolicy: Qt.NoFocus
                Accessible.role: Accessible.ListItem
                Accessible.name: qsTr("%1, %2, %3, %4").arg(name)
                    .arg(direction === "out" ? qsTr("sent") : qsTr("received")).arg(size).arg(time)
                Accessible.selected: selected

                onClicked: {
                    list.forceActiveFocus()
                    view.inspector.selectFrame(ordinal)
                }

                contentItem: RowLayout {
                    id: lines
                    spacing: Theme.s2

                    AppText {
                        Layout.alignment: Qt.AlignTop
                        text: entry.direction === "out" ? "→" : "←"
                        color: entry.selected ? Theme.selectionText : Theme.textSecondary
                        Accessible.ignored: true
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0

                        AppText {
                            Layout.fillWidth: true
                            text: entry.name
                            elide: Text.ElideRight
                            font.weight: entry.selected ? Theme.weightMedium : Theme.weightRegular
                            color: entry.selected ? Theme.selectionText : Theme.text
                        }
                        AppText {
                            Layout.fillWidth: true
                            text: entry.size + "  ·  " + entry.time
                            role: "small"
                            elide: Text.ElideRight
                            color: entry.selected ? Theme.selectionText : Theme.textSecondary
                        }
                    }
                }
                background: Rectangle {
                    color: entry.selected ? Theme.selectionFill : entry.hovered ? Theme.hoverFill : "transparent"
                }
            }
        }

        Divider {
            vertical: view.wide
            Layout.fillWidth: !view.wide
            Layout.fillHeight: view.wide
        }

        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: Theme.s4

            FrameDetail {
                anchors.fill: parent
                visible: view.inspector.selectedFrame >= 0
                inspector: view.inspector
            }
            AppText {
                anchors.left: parent.left
                anchors.right: parent.right
                visible: view.inspector.selectedFrame < 0
                text: list.count > 0
                    ? qsTr("Select a frame to see its 5-byte header, its fields and its bytes as transmitted.")
                    : qsTr("No frames captured yet.")
                role: "secondary"
                wrapMode: Text.Wrap
            }
        }
    }
}
