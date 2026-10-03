import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// The selected timeline row: a frame's fields and bytes, or what a local event, a group, the
// close or a gap means, with the view that shows more of it.
Item {
    id: detail

    required property var inspector
    readonly property var row: {
        const key = inspector.selectedRow
        const index = key !== "" ? inspector.timeline.indexOf(key) : -1
        return index >= 0 ? inspector.timeline.get(index) : null
    }
    readonly property bool showsFrame: row !== null && row.frame >= 0 && row.frame === inspector.selectedFrame

    FrameDetail {
        anchors.fill: parent
        visible: detail.showsFrame
        inspector: detail.inspector
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        visible: !detail.showsFrame
        spacing: Theme.s3

        AppText {
            Layout.fillWidth: true
            visible: detail.row === null
            text: qsTr("Select an event to see its bytes, fields and what it means.")
            role: "secondary"
            wrapMode: Text.Wrap
        }
        AppText {
            Layout.fillWidth: true
            visible: detail.row !== null
            text: detail.row ? detail.row.title : ""
            role: "title"
            wrapMode: Text.Wrap
            color: detail.row && detail.row.tone === "danger" ? Theme.dangerText : Theme.text
            Accessible.role: Accessible.Heading
        }
        AppText {
            Layout.fillWidth: true
            visible: detail.row !== null
            text: detail.row ? [detail.row.time, detail.row.detail].filter(p => p !== "").join(" · ") : ""
            role: "secondary"
            wrapMode: Text.Wrap
        }
        AppText {
            Layout.fillWidth: true
            visible: text !== ""
            text: detail.row ? detail.explain(detail.row) : ""
            wrapMode: Text.Wrap
        }
        RowLayout {
            spacing: Theme.s2
            visible: detail.row !== null

            AppButton {
                visible: detail.row !== null && detail.row.kind === "group"
                compact: true
                iconName: detail.row && detail.row.expanded ? "chevron-down" : "chevron-right"
                text: detail.row && detail.row.expanded ? qsTr("Fold the records")
                    : qsTr("List the %n records", "", detail.row ? detail.row.count : 0)
                onClicked: detail.inspector.toggleGroup(detail.row.key)
            }
            AppButton {
                visible: detail.row !== null && (detail.row.kind === "schedule" || detail.row.tone === "accent")
                compact: true
                iconName: "key-round"
                text: qsTr("Show in Keys")
                onClicked: detail.inspector.setView("keys")
            }
            AppButton {
                visible: detail.row !== null && detail.row.kind === "closed"
                compact: true
                iconName: "shield"
                text: qsTr("Show in Security")
                onClicked: detail.inspector.setView("security")
            }
        }
    }

    function explain(row) {
        switch (row.kind) {
        case "schedule":
            return inspector.exposure === "public"
                ? qsTr("Derivations and transcript hashes the engine reported. Their names and sizes are public; their values stay hidden in a normal session.")
                : qsTr("Derivations and transcript hashes the engine reported. This session is exposed: Keys shows their values.")
        case "local":
            return row.tone === "accent"
                ? qsTr("This side's key state changed, as its engine reported. Each direction changes keys on its own: the other may still be on its previous epoch or generation.")
                : qsTr("A transition of this side's state machine, as its engine reported it.")
        case "group":
            return qsTr("Records of the same kinds in a row, folded. Their bodies are sealed; the kind is known to this side's engine, it is not readable on the wire.")
        case "closed":
            return qsTr("The session ended here. A reason names what failed, not who caused it: the receiver cannot tell an attack from a fault.")
        case "gap":
            return qsTr("The trace bus keeps a session's handshake and its latest 10,000 events (at most 4 MiB). Older events were dropped before this display took them.")
        default:
            return ""
        }
    }
}
