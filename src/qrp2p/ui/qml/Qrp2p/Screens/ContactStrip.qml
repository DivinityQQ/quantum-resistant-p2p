import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// The few most recent contacts plus the selected one, an All contacts chooser and a way to reach
// someone new (UI_DESIGN §3.1). It never wraps into extra rows: fewer chips show as space runs out.
Item {
    id: strip

    required property var workspace

    signal openChooser()
    signal openConnect()

    implicitHeight: 72

    readonly property int chipWidth: 196
    onWidthChanged: Qt.callLater(fit)
    Component.onCompleted: fit()

    function fit() {
        const room = width - allButton.implicitWidth - addButton.implicitWidth - Theme.s6 * 2 - Theme.s2 * 3
        workspace.setStripLimit(Math.max(1, Math.floor(room / chipWidth)))
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Theme.s6 - Theme.s3
        anchors.rightMargin: Theme.s4
        spacing: Theme.s2

        Repeater {
            model: strip.workspace.strip

            ContactChip {
                selected: contactId === strip.workspace.selectedId
                onClicked: strip.workspace.select(contactId)
            }
        }
        Item {
            Layout.fillWidth: true
        }
        AppButton {
            id: allButton
            kind: "quiet"
            iconName: "users"
            text: strip.workspace.contactCount > 0
                ? qsTr("All contacts (%1)").arg(strip.workspace.contactCount) : qsTr("Contacts")
            toolTipText: strip.workspace.hiddenUnread > 0
                ? qsTr("%n unread in contacts not shown here", "", strip.workspace.hiddenUnread)
                : qsTr("Search contacts and nearby people (Ctrl+K)")
            onClicked: strip.openChooser()

            Rectangle {
                visible: strip.workspace.hiddenUnread > 0
                width: 8
                height: 8
                radius: 4
                color: Theme.primaryFill
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: 6
                Accessible.ignored: true
            }
        }
        IconButton {
            id: addButton
            label: qsTr("Connect to someone new (Ctrl+N)")
            iconName: "user-plus"
            onClicked: strip.openConnect()
        }
    }
}
