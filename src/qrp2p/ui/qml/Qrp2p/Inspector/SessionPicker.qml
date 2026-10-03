import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Which retained session the Inspector shows: the open ones and the recently ended or failed
// ones the trace bus still keeps, newest first.
T.Button {
    id: control

    required property var inspector

    objectName: "sessionPicker"
    implicitHeight: Theme.controlHeight
    implicitWidth: Math.min(320, content.implicitWidth + leftPadding + rightPadding)
    leftPadding: Theme.s3
    rightPadding: Theme.s2
    hoverEnabled: true
    focusPolicy: Qt.StrongFocus
    enabled: inspector.sessions.count > 0
    Accessible.role: Accessible.ComboBox
    Accessible.name: qsTr("Inspected session: %1").arg(inspector.title || qsTr("none"))

    onClicked: popup.visible ? popup.close() : popup.open()

    contentItem: RowLayout {
        id: content
        spacing: Theme.s2

        AppText {
            Layout.fillWidth: true
            text: control.inspector.sessionId >= 0
                ? control.inspector.title + " · " + control.inspector.subtitle
                : qsTr("No session")
            elide: Text.ElideRight
            role: "small"
            color: control.enabled ? Theme.text : Theme.textSecondary
        }
        Icon {
            name: "chevron-down"
            size: Theme.iconSize - 2
            color: Theme.textSecondary
        }
    }
    background: Rectangle {
        radius: Theme.radiusControl
        color: control.down ? Theme.pressedFill : control.hovered ? Theme.hoverFill : Theme.surface
        border.width: 1
        border.color: control.enabled ? Theme.controlBoundary : Theme.divider

        FocusRing {
            visible: control.visualFocus
        }
    }

    T.Popup {
        id: popup
        objectName: "sessionPopup"
        y: control.height + Theme.s1
        x: control.width - width
        width: 340
        implicitHeight: Math.min(list.contentHeight + topPadding + bottomPadding, 380)
        padding: Theme.s1
        focus: true
        closePolicy: T.Popup.CloseOnEscape | T.Popup.CloseOnPressOutsideParent

        onOpened: {
            list.currentIndex = Math.max(0, control.inspector.sessions.indexOf(String(control.inspector.sessionId)))
            list.forceActiveFocus()
        }
        onClosed: control.forceActiveFocus()

        contentItem: ListView {
            id: list
            clip: true
            implicitHeight: contentHeight
            model: control.inspector.sessions
            keyNavigationEnabled: true
            highlightMoveDuration: 0
            Accessible.role: Accessible.List
            Accessible.name: qsTr("Retained sessions")
            T.ScrollBar.vertical: AppScrollBar {
                id: bar
            }
            Keys.onReturnPressed: currentItem && currentItem.choose()
            Keys.onEnterPressed: currentItem && currentItem.choose()
            Keys.onSpacePressed: currentItem && currentItem.choose()

            delegate: T.ItemDelegate {
                id: entry

                required property int index
                required property int sessionId
                required property string title
                required property string subtitle
                required property var model
                required property string exposure
                readonly property bool chosen: sessionId === control.inspector.sessionId

                objectName: "session-" + sessionId
                width: ListView.view.width - bar.gutter
                implicitHeight: lines.implicitHeight + Theme.s2 * 2
                leftPadding: Theme.s3
                rightPadding: Theme.s3
                hoverEnabled: true
                highlighted: ListView.isCurrentItem
                Accessible.role: Accessible.ListItem
                Accessible.name: title + ", " + subtitle

                function choose() {
                    control.inspector.chooseSession(sessionId)
                    popup.close()
                }
                onClicked: choose()

                contentItem: RowLayout {
                    id: lines
                    spacing: Theme.s2

                    Icon {
                        name: entry.model.state === "failed" ? "circle-alert"
                            : entry.model.state === "ended" ? "unplug"
                            : entry.model.state === "handshake" ? "loader-circle" : "link-2"
                        color: entry.model.state === "failed" ? Theme.dangerText : Theme.textSecondary
                        size: Theme.iconSize - 2
                        Layout.alignment: Qt.AlignTop
                        Layout.topMargin: 2
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0

                        AppText {
                            Layout.fillWidth: true
                            text: entry.title
                            elide: Text.ElideRight
                            font.weight: entry.chosen ? Theme.weightMedium : Theme.weightRegular
                        }
                        AppText {
                            Layout.fillWidth: true
                            text: entry.subtitle
                            role: "small"
                            elide: Text.ElideRight
                            color: entry.model.state === "failed" ? Theme.dangerText : Theme.textSecondary
                        }
                    }
                    Tag {
                        visible: entry.exposure === "glass_box"
                        text: qsTr("GLASS-BOX")
                        kind: "exposure"
                    }
                    Icon {
                        visible: entry.chosen
                        name: "check"
                        size: Theme.iconSize - 2
                    }
                }
                background: Rectangle {
                    radius: Theme.radiusTight + 2
                    color: entry.highlighted || entry.hovered ? Theme.hoverFill : "transparent"
                }
            }
        }
        background: Rectangle {
            color: Theme.surface
            radius: Theme.radiusControl + 2
            border.width: 1
            border.color: Theme.divider
        }
    }
}
