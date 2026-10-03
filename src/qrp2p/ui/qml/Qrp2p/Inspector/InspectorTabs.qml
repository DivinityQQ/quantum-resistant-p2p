import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// The Inspector's views as tabs. Arrow keys, Home and End move between them and activate the
// one they land on (UI_DESIGN §12); the shown tab always follows `current` from the view model.
Item {
    id: tabs

    property string current: "timeline"
    readonly property var options: [
        { value: "timeline", label: qsTr("Timeline"), icon: "clock" },
        { value: "messages", label: qsTr("Messages"), icon: "file" },
        { value: "keys", label: qsTr("Keys"), icon: "key-round" },
        { value: "security", label: qsTr("Security"), icon: "shield" }
    ]

    signal chosen(string value)

    implicitWidth: row.implicitWidth
    implicitHeight: row.implicitHeight
    Accessible.role: Accessible.PageTabList
    Accessible.name: qsTr("Inspector views")

    function focusCurrent() {
        for (let i = 0; i < repeater.count; ++i)
            if (options[i].value === current)
                repeater.itemAt(i).forceActiveFocus(Qt.TabFocusReason)
    }

    function move(index) {
        const next = Math.max(0, Math.min(options.length - 1, index))
        chosen(options[next].value)
        repeater.itemAt(next).forceActiveFocus(Qt.TabFocusReason)
    }

    Row {
        id: row
        spacing: Theme.s1

        Repeater {
            id: repeater
            model: tabs.options

            T.TabButton {
                id: tab

                required property var modelData
                required property int index
                readonly property bool selected: modelData.value === tabs.current

                objectName: "inspectorTab-" + modelData.value
                implicitHeight: Theme.controlHeight
                implicitWidth: content.implicitWidth + Theme.s3 * 2
                hoverEnabled: true
                focusPolicy: Qt.StrongFocus
                checked: selected
                Accessible.role: Accessible.PageTab
                Accessible.name: modelData.label
                Accessible.selected: selected

                onClicked: tabs.chosen(modelData.value)
                Keys.onLeftPressed: tabs.move(index - 1)
                Keys.onRightPressed: tabs.move(index + 1)
                Keys.onPressed: event => {
                    if (event.key === Qt.Key_Home) {
                        tabs.move(0)
                        event.accepted = true
                    } else if (event.key === Qt.Key_End) {
                        tabs.move(tabs.options.length - 1)
                        event.accepted = true
                    }
                }

                contentItem: Item {
                    implicitWidth: content.implicitWidth
                    implicitHeight: content.implicitHeight

                    Row {
                        id: content
                        anchors.centerIn: parent
                        spacing: Theme.s2

                        Icon {
                            name: tab.modelData.icon
                            color: tab.selected ? Theme.text : Theme.textSecondary
                            anchors.verticalCenter: parent.verticalCenter
                        }
                        AppText {
                            text: tab.modelData.label
                            font.weight: tab.selected ? Theme.weightMedium : Theme.weightRegular
                            color: tab.selected ? Theme.text : Theme.textSecondary
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }
                }
                background: Rectangle {
                    radius: Theme.radiusControl
                    color: tab.selected ? Theme.surfaceSubtle
                        : tab.down ? Theme.pressedFill
                        : tab.hovered ? Theme.hoverFill : "transparent"

                    FocusRing {
                        visible: tab.visualFocus
                    }
                }
            }
        }
    }
}
