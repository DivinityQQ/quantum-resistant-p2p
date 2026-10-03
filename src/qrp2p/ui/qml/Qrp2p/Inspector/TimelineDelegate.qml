import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// One row of the sequence diagram. The initiator's lane is on the left, the responder's on the
// right; a frame or record is a card with an arrow from its sender's lane to its receiver's.
// Local events (state changes, derivations, key switches) are notes on the local lane only: the
// peer lane is the other participant, never something measured on its host (UI_DESIGN §7.2).
Item {
    id: row

    required property var inspector
    required property bool localLeft
    required property int index
    required property string key
    required property string kind
    required property string time
    required property string direction
    required property string title
    required property string detail
    required property string tone
    required property bool member
    required property bool expanded

    readonly property bool selected: key === inspector.selectedRow
    readonly property bool card: kind === "frame" || kind === "record" || kind === "group" || kind === "closed"
    readonly property bool note: kind === "schedule" || kind === "local"
    // Which lane sent it: true for the left lane; the local lane for "out".
    readonly property bool fromLeft: direction === "out" ? localLeft : !localLeft
    readonly property int lane: 20
    readonly property int inset: member ? 64 : 44
    readonly property string who: direction === "out"
        ? inspector.localName + " → " + inspector.peerName
        : direction === "in" ? inspector.peerName + " → " + inspector.localName : ""

    signal activated()

    implicitHeight: card ? cardBox.implicitHeight + Theme.s2 * 2
        : note ? noteRow.implicitHeight + Theme.s2 * 1.5
        : gapRow.implicitHeight + Theme.s4 * 2
    Accessible.role: Accessible.ListItem
    Accessible.name: [title, detail, who, time].filter(part => part !== "").join(", ")
    Accessible.selected: selected

    // The two lanes run through every row.
    Rectangle {
        x: row.lane
        width: 1
        height: parent.height
        color: Theme.divider
    }
    Rectangle {
        x: row.width - row.lane - 1
        width: 1
        height: parent.height
        color: Theme.divider
    }

    // -- frames, records, groups and the close ----------------------------------------------------

    Rectangle {
        id: cardBox
        visible: row.card
        x: row.inset
        width: row.width - row.inset * 2
        anchors.verticalCenter: parent.verticalCenter
        implicitHeight: cardText.implicitHeight + Theme.s2 * 2
        radius: Theme.radiusControl
        color: row.selected ? Theme.selectionFill
            : row.kind === "closed" && row.tone === "danger" ? Theme.dangerFill
            : pointer.hovered ? Theme.hoverFill : Theme.surface
        border.width: 1
        border.color: row.selected ? Theme.selectionText : Theme.divider

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.s3
            anchors.rightMargin: Theme.s3
            spacing: Theme.s2

            Icon {
                visible: row.kind === "group" || row.kind === "closed" || row.tone === "accent"
                name: row.kind === "group" ? (row.expanded ? "chevron-down" : "chevron-right")
                    : row.kind === "closed" ? (row.tone === "danger" ? "circle-alert" : "unplug")
                    : "refresh-cw"
                color: row.tone === "danger" ? Theme.dangerText : Theme.textSecondary
                size: Theme.iconSize - 2
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 2
            }
            ColumnLayout {
                id: cardText
                Layout.fillWidth: true
                spacing: 0

                AppText {
                    Layout.fillWidth: true
                    text: row.title
                    elide: Text.ElideRight
                    font.weight: Theme.weightMedium
                    color: row.selected ? Theme.selectionText
                        : row.tone === "danger" ? Theme.dangerText : Theme.text
                }
                AppText {
                    Layout.fillWidth: true
                    text: [row.time, row.who].filter(part => part !== "").join("  ·  ")
                    role: "small"
                    elide: Text.ElideRight
                }
                AppText {
                    Layout.fillWidth: true
                    visible: row.detail !== ""
                    text: row.detail
                    role: "small"
                    elide: Text.ElideRight
                }
            }
            // The arrow points from the sender's lane towards the receiver's.
            Item {
                visible: row.direction !== "" && row.kind !== "closed"
                Layout.preferredWidth: 56
                Layout.preferredHeight: Theme.iconSize

                Rectangle {
                    x: row.fromLeft ? 0 : 6
                    width: parent.width - 6
                    height: 1.5
                    anchors.verticalCenter: parent.verticalCenter
                    color: row.selected ? Theme.selectionText : Theme.controlBoundary
                }
                Icon {
                    x: row.fromLeft ? parent.width - width + 4 : -4
                    anchors.verticalCenter: parent.verticalCenter
                    name: row.fromLeft ? "chevron-right" : "chevron-left"
                    color: row.selected ? Theme.selectionText : Theme.controlBoundary
                }
            }
        }
        HoverHandler {
            id: pointer
        }
        TapHandler {
            onTapped: row.activated()
        }
    }

    // Where it left and arrived: a filled dot on the sender's lane, a ring on the receiver's.
    Repeater {
        model: row.card && row.kind !== "closed" ? 2 : 0

        Rectangle {
            required property int index
            readonly property bool leftLane: index === 0
            readonly property bool sender: row.direction !== "" && leftLane === row.fromLeft

            x: (leftLane ? row.lane : row.width - row.lane - 1) - width / 2 + 0.5
            anchors.verticalCenter: parent.verticalCenter
            width: 9
            height: 9
            radius: 4.5
            color: sender ? (row.selected ? Theme.selectionText : Theme.text) : Theme.canvas
            border.width: 1.5
            border.color: row.selected ? Theme.selectionText : Theme.controlBoundary
        }
    }

    // -- local notes ----------------------------------------------------------------------------

    Rectangle {
        visible: row.note
        x: (row.localLeft ? row.lane : row.width - row.lane - 1) - 3 + 0.5
        anchors.verticalCenter: parent.verticalCenter
        width: 6
        height: 6
        radius: 3
        color: row.tone === "accent" ? Theme.text : Theme.controlBoundary
    }
    Rectangle {
        id: noteBox
        visible: row.note
        anchors.verticalCenter: parent.verticalCenter
        x: row.localLeft ? row.lane + Theme.s3 : row.width - row.lane - Theme.s3 - width
        width: Math.min(noteRow.implicitWidth + Theme.s2 * 2, row.width - row.lane * 2 - Theme.s3 * 2)
        height: noteRow.implicitHeight + Theme.s1 * 2
        radius: Theme.radiusTight + 2
        color: row.selected ? Theme.selectionFill : notePointer.hovered ? Theme.hoverFill : "transparent"

        RowLayout {
            id: noteRow
            anchors.fill: parent
            anchors.leftMargin: Theme.s2
            anchors.rightMargin: Theme.s2
            spacing: Theme.s2
            layoutDirection: row.localLeft ? Qt.LeftToRight : Qt.RightToLeft

            Icon {
                name: row.kind === "schedule" ? "key-round" : row.tone === "accent" ? "refresh-cw" : "chevron-right"
                size: Theme.sizeSmall + 2
                color: row.selected ? Theme.selectionText : Theme.textSecondary
            }
            AppText {
                Layout.fillWidth: true
                text: row.detail !== "" ? row.title + " · " + row.detail : row.title
                role: "small"
                elide: Text.ElideRight
                horizontalAlignment: row.localLeft ? Text.AlignLeft : Text.AlignRight
                color: row.selected ? Theme.selectionText
                    : row.tone === "accent" ? Theme.text : Theme.textSecondary
            }
        }
        HoverHandler {
            id: notePointer
        }
        TapHandler {
            onTapped: row.activated()
        }
    }

    // -- a gap in the retained events -------------------------------------------------------------

    RowLayout {
        id: gapRow
        visible: row.kind === "gap"
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: row.lane + Theme.s3
        anchors.rightMargin: row.lane + Theme.s3
        spacing: Theme.s2

        Divider {
            Layout.fillWidth: true
        }
        AppText {
            Layout.maximumWidth: row.width - row.lane * 2 - Theme.s8 * 2
            text: row.title + " · " + row.detail
            role: "small"
            elide: Text.ElideRight
        }
        Divider {
            Layout.fillWidth: true
        }
    }
}
