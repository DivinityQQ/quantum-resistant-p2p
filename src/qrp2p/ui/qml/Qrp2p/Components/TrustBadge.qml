import QtQuick
import Qrp2p.Theme

// The trust state in words with its shield. Verified means a human compared safety numbers; a
// successful signature check alone never earns it (UI_DESIGN §6.4).
Row {
    id: badge

    // verified | pinned | blocked
    property string trust: "pinned"
    property bool compact: false

    spacing: Theme.s1
    Accessible.role: Accessible.StaticText
    Accessible.name: label.text

    Icon {
        anchors.verticalCenter: parent.verticalCenter
        size: badge.compact ? Theme.iconSize - 4 : Theme.iconSize - 2
        name: badge.trust === "verified" ? "shield-check" : badge.trust === "blocked" ? "ban" : "shield"
        color: label.color
    }
    AppText {
        id: label
        anchors.verticalCenter: parent.verticalCenter
        visible: !badge.compact
        role: "small"
        text: badge.trust === "verified" ? qsTr("Verified")
            : badge.trust === "blocked" ? qsTr("Blocked") : qsTr("Not verified")
        color: badge.trust === "verified" ? Theme.success
            : badge.trust === "blocked" ? Theme.dangerText : Theme.textSecondary
    }
}
