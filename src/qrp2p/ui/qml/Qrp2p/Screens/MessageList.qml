import QtQuick
import QtQuick.Controls.Basic
import Qrp2p.Theme
import Qrp2p.Components

// The conversation's messages. The list follows the newest message only while the user is at
// the end; scrolled up, it keeps its place and offers a jump to the new messages (UI_DESIGN §3.2).
ListView {
    id: list

    required property var conversation
    property int columnWidth: 600
    property bool following: true
    property int unseen: 0
    // The newest entry seen so far: only rows added after it are new (loading earlier history
    // adds rows at the top, which are not).
    property string lastEntry: ""

    signal saveTo(string fileId)
    signal verify()

    model: conversation.messagesModel
    clip: true
    spacing: 0
    reuseItems: false
    boundsBehavior: Flickable.StopAtBounds
    keyNavigationEnabled: false
    activeFocusOnTab: false
    ScrollBar.vertical: AppScrollBar {
        id: scrollbar
    }
    Accessible.role: Accessible.List
    Accessible.name: qsTr("Messages with %1").arg(conversation.name)

    header: Item {
        width: list.width
        height: earlier.visible ? earlier.height + Theme.s6 : Theme.s4

        AppButton {
            id: earlier
            visible: list.conversation.hasEarlier
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            kind: "quiet"
            compact: true
            busy: list.conversation.loading
            text: qsTr("Show earlier messages")
            onClicked: list.conversation.loadEarlier()
        }
    }
    footer: Item {
        width: list.width
        height: Theme.s4
    }

    delegate: MessageDelegate {
        conversation: list.conversation
        columnWidth: list.columnWidth
        onSaveTo: id => list.saveTo(id)
        onVerify: list.verify()
    }

    function jumpToEnd() {
        following = true
        unseen = 0
        positionViewAtEnd()
    }

    function userMoved() {
        return moving || dragging || flicking || scrollbar.pressed
    }

    onCountChanged: {
        const last = count > 0 ? model.get(count - 1).entryId : ""
        const appended = last !== lastEntry && lastEntry !== ""
        lastEntry = last
        if (following)
            Qt.callLater(positionViewAtEnd)
        else if (appended)
            unseen += 1
    }
    onContentHeightChanged: if (following) Qt.callLater(positionViewAtEnd)
    onHeightChanged: if (following) Qt.callLater(positionViewAtEnd)
    onAtYEndChanged: {
        if (userMoved() || scrollbar.active) {
            following = atYEnd
            if (atYEnd)
                unseen = 0
        }
    }
    onMovementEnded: {
        following = atYEnd
        if (atYEnd)
            unseen = 0
    }
    Component.onCompleted: positionViewAtEnd()

    AppButton {
        visible: !list.following && list.count > 0
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: Theme.s4
        kind: "secondary"
        compact: true
        iconName: "arrow-down"
        text: list.unseen > 0 ? qsTr("%n new", "", list.unseen) : qsTr("Latest")
        onClicked: list.jumpToEnd()
    }
}
