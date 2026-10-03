import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Timeline: the session as a sequence diagram beside (or above) the selected event's detail.
// The list follows new events only while it is at its end; scrolled up, it keeps its place.
// Up and Down move the selection; Enter or Space folds or lists a group of records.
Item {
    id: view

    required property var inspector
    readonly property bool wide: width >= 860 * Math.max(1, Theme.scale)

    GridLayout {
        anchors.fill: parent
        columns: view.wide ? 3 : 1
        rowSpacing: 0
        columnSpacing: 0

        ColumnLayout {
            Layout.preferredWidth: view.wide ? Math.max(340, Math.round(view.width * 0.44)) : -1
            Layout.fillWidth: !view.wide
            Layout.fillHeight: view.wide
            Layout.preferredHeight: view.wide ? -1 : Math.round(view.height * 0.5)
            spacing: 0

            // The lanes: initiator on the left, responder on the right.
            Item {
                Layout.fillWidth: true
                implicitHeight: lanes.implicitHeight + Theme.s3 * 2

                RowLayout {
                    id: lanes
                    anchors.fill: parent
                    anchors.leftMargin: Theme.s3
                    anchors.rightMargin: Theme.s3

                    ColumnLayout {
                        spacing: 0
                        AppText {
                            text: view.inspector.initiator ? view.inspector.localName : view.inspector.peerName
                            font.weight: Theme.weightMedium
                            elide: Text.ElideRight
                            Layout.maximumWidth: lanes.width / 2 - Theme.s2
                        }
                        AppText {
                            text: qsTr("Initiator")
                            role: "small"
                        }
                    }
                    // The clock's origin, between the lanes: elapsed time is local, never the peer's.
                    AppText {
                        Layout.fillWidth: true
                        Layout.leftMargin: Theme.s2
                        Layout.rightMargin: Theme.s2
                        horizontalAlignment: Text.AlignHCenter
                        text: qsTr("Times: this device's clock, from the first retained event")
                        role: "small"
                        wrapMode: Text.Wrap
                        maximumLineCount: 2
                        elide: Text.ElideRight
                    }
                    ColumnLayout {
                        spacing: 0
                        AppText {
                            Layout.alignment: Qt.AlignRight
                            text: view.inspector.initiator ? view.inspector.peerName : view.inspector.localName
                            font.weight: Theme.weightMedium
                            elide: Text.ElideRight
                            Layout.maximumWidth: lanes.width / 2 - Theme.s2
                        }
                        AppText {
                            Layout.alignment: Qt.AlignRight
                            text: qsTr("Responder")
                            role: "small"
                        }
                    }
                }
            }

            ListView {
                id: list

                property bool atEnd: true

                objectName: "timelineList"
                Layout.fillWidth: true
                Layout.fillHeight: true
                model: view.inspector.timeline
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                keyNavigationEnabled: false
                activeFocusOnTab: true
                reuseItems: true
                function selected() { return view.inspector.timeline.indexOf(view.inspector.selectedRow) }
                highlightMoveDuration: 0
                T.ScrollBar.vertical: AppScrollBar {
                    id: bar
                }
                Accessible.role: Accessible.List
                Accessible.name: qsTr("Session events")

                delegate: TimelineDelegate {
                    width: list.width - bar.gutter
                    inspector: view.inspector
                    localLeft: view.inspector.initiator
                    onActivated: {
                        list.forceActiveFocus()
                        list.atEnd = index === list.count - 1  // reading an older event: stay there
                        view.inspector.selectRow(key)
                        if (kind === "group")
                            view.inspector.toggleGroup(key)
                    }
                }

                footer: Item {
                    width: list.width
                    height: Theme.s4
                }

                function step(delta) {
                    if (count === 0)
                        return
                    const current = selected()
        const from = current < 0 ? (delta > 0 ? -1 : count) : current
                    const next = Math.max(0, Math.min(count - 1, from + delta))
                    view.inspector.selectRow(view.inspector.timeline.get(next).key)
                    positionViewAtIndex(next, ListView.Contain)
                    atEnd = next === count - 1
                }
                Keys.onUpPressed: step(-1)
                Keys.onDownPressed: step(1)
                Keys.onPressed: event => {
                    if (event.key === Qt.Key_Home) {
                        step(-count)
                        event.accepted = true
                    } else if (event.key === Qt.Key_End) {
                        step(count)
                        event.accepted = true
                    }
                }
                function toggle() {
                    const index = selected()
                    const row = index >= 0 ? view.inspector.timeline.get(index) : null
                    if (row && row.kind === "group")
                        view.inspector.toggleGroup(row.key)
                }
                Keys.onReturnPressed: toggle()
                Keys.onEnterPressed: toggle()
                Keys.onSpacePressed: toggle()

                // A newly selected row comes into view; a live update to the same row never moves
                // the list (the reader may have scrolled away from it).
                property string shown: ""
                Connections {
                    target: view.inspector
                    function onSelectionChanged() {
                        if (view.inspector.selectedRow === list.shown)
                            return
                        list.shown = view.inspector.selectedRow
                        const index = list.selected()
                        if (index >= 0)
                            list.positionViewAtIndex(index, ListView.Contain)
                    }
                }

                // Follow the end while it is in view; never move a reader who scrolled up.
                onMovementEnded: atEnd = atYEnd
                onAtYEndChanged: if (bar.pressed) atEnd = atYEnd
                onCountChanged: if (atEnd && view.inspector.following) Qt.callLater(positionViewAtEnd)
                Component.onCompleted: {
                    const index = selected()
                    if (index >= 0)
                        positionViewAtIndex(index, ListView.Center)
                    else
                        positionViewAtEnd()
                }

                FocusRing {
                    visible: list.activeFocus
                    anchors.margins: 0
                    cornerRadius: 0
                }
            }

        }

        Divider {
            vertical: view.wide
            Layout.fillWidth: !view.wide
            Layout.fillHeight: view.wide
        }

        EventDetail {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: Theme.s4
            inspector: view.inspector
        }
    }
}
