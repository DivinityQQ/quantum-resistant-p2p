import QtQuick
import Qrp2p.Theme

// Short notices at the bottom of the window, one at a time, each for a few seconds. They are
// announced to screen readers; nothing important lives only here.
Item {
    id: host

    property var queue: []
    property string current: ""

    function show(text) {
        if (!text)
            return
        queue = queue.concat([text])
        if (!current)
            next()
    }

    function next() {
        if (queue.length === 0) {
            current = ""
            return
        }
        current = queue[0]
        queue = queue.slice(1)
        timer.restart()
    }

    // Near the top, under the title bar: the newest message and the composer stay visible.
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.top: parent.top
    anchors.topMargin: 64
    height: toast.height
    z: 1000

    Timer {
        id: timer
        interval: 4500
        onTriggered: host.next()
    }

    Rectangle {
        id: toast
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        width: Math.min(message.implicitWidth + Theme.s4 * 2, host.width - Theme.s8 * 2)
        height: message.implicitHeight + Theme.s3 * 2
        radius: Theme.radiusControl
        color: Theme.primaryFill
        opacity: host.current ? 1 : 0
        visible: opacity > 0
        Accessible.role: Accessible.AlertMessage
        Accessible.name: host.current

        Behavior on opacity {
            NumberAnimation { duration: Theme.motion }
        }

        AppText {
            id: message
            anchors.centerIn: parent
            width: Math.min(implicitWidth, host.width - Theme.s8 * 2 - Theme.s4 * 2)
            text: host.current
            color: Theme.primaryText
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
        }

        MouseArea {
            anchors.fill: parent
            onClicked: host.next()
        }
    }
}
