import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components

// The Session Inspector (UI_DESIGN §3.3, §7): one session's trace as a timeline, its captured
// frames, its key schedule and its security facts, sharing one selection. Only the visible view
// is built. Pausing freezes this display; the session and its networking carry on.
Item {
    id: pane

    required property var inspector
    property bool split: true          // the chat is visible beside it
    property bool expanded: false
    property bool canExpand: false

    signal backToChat()
    signal toggleExpanded()

    objectName: "inspectorPane"
    // Room for labels beside the icons in the header, at the current text size.
    readonly property bool roomy: width >= 760 * Math.max(1, Theme.scale)

    function focusTabs() {
        tabs.focusCurrent()
    }

    Rectangle {
        anchors.fill: parent
        color: Theme.canvas
    }
    Divider {
        vertical: true
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        visible: pane.split && !pane.expanded
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 1
        spacing: 0

        // -- heading, exposure, session and following -------------------------------------------
        // When space runs short the title elides first, then the session picker narrows; the
        // exposure tag always keeps its full text.
        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: Theme.s4
            Layout.rightMargin: Theme.s4
            Layout.topMargin: Theme.s3
            Layout.bottomMargin: Theme.s2
            spacing: Theme.s2

            AppButton {
                visible: !pane.split
                kind: "quiet"
                compact: true
                iconName: "arrow-left"
                text: pane.roomy ? qsTr("Back to chat") : ""
                toolTipText: qsTr("Back to chat")
                onClicked: pane.backToChat()
            }
            AppText {
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                Layout.preferredWidth: Math.ceil(implicitWidth)
                Layout.maximumWidth: Math.ceil(implicitWidth)
                text: qsTr("Session Inspector")
                role: "title"
                elide: Text.ElideRight
                Accessible.role: Accessible.Heading
            }
            Tag {
                visible: pane.inspector.exposure !== ""
                objectName: "exposureTag"
                text: pane.inspector.exposure === "glass_box" ? qsTr("GLASS-BOX")
                    : pane.inspector.exposure === "lab" ? qsTr("LAB") : qsTr("PUBLIC TRACE")
                kind: pane.inspector.exposure === "glass_box" ? "exposure"
                    : pane.inspector.exposure === "lab" ? "lab" : "neutral"
                iconName: pane.inspector.exposure === "glass_box" ? "eye"
                    : pane.inspector.exposure === "lab" ? "flask-conical" : "eye-off"
            }
            Item {
                Layout.fillWidth: true
            }
            SessionPicker {
                Layout.fillWidth: true
                Layout.minimumWidth: 120
                Layout.maximumWidth: 320
                inspector: pane.inspector
            }
            AppButton {
                objectName: "followButton"
                kind: "quiet"
                compact: true
                enabled: pane.inspector.sessionId >= 0
                iconName: pane.inspector.following ? "pause" : "play"
                text: pane.roomy ? (pane.inspector.following ? qsTr("Pause") : qsTr("Follow live")) : ""
                toolTipText: pane.inspector.following
                    ? qsTr("Pause following: freeze this display; the session carries on")
                    : qsTr("Follow live: catch up and show new events again")
                onClicked: pane.inspector.following ? pane.inspector.pause() : pane.inspector.followLive()
            }
            IconButton {
                visible: pane.canExpand
                label: pane.expanded ? qsTr("Restore split") : qsTr("Expand Inspector")
                iconName: pane.expanded ? "minimize-2" : "maximize-2"
                onClicked: pane.toggleExpanded()
            }
        }

        InspectorTabs {
            id: tabs
            Layout.leftMargin: Theme.s4
            Layout.bottomMargin: Theme.s2
            current: pane.inspector.view
            onChosen: value => pane.inspector.setView(value)
        }
        Divider {
            Layout.fillWidth: true
        }

        // -- the visible view, or why there is none ------------------------------------------------
        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Loader {
                anchors.fill: parent
                active: pane.inspector.sessionId >= 0 && pane.inspector.error === ""
                sourceComponent: {
                    switch (pane.inspector.view) {
                    case "messages": return messagesView
                    case "keys": return keysView
                    case "security": return securityView
                    default: return timelineView
                    }
                }
            }

            ColumnLayout {
                anchors.centerIn: parent
                width: Math.min(440, parent.width - Theme.s6 * 2)
                visible: pane.inspector.sessionId < 0 || pane.inspector.error !== ""
                spacing: Theme.s3

                Icon {
                    Layout.alignment: Qt.AlignHCenter
                    name: pane.inspector.error !== "" ? "history" : "panel-right"
                    size: 36
                    color: Theme.textSecondary
                }
                AppText {
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignHCenter
                    text: pane.inspector.error !== "" ? qsTr("This session is not available")
                        : qsTr("No session to inspect")
                    role: "title"
                    wrapMode: Text.Wrap
                }
                AppText {
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignHCenter
                    text: pane.inspector.error !== ""
                        ? qsTr("%1 Choose another session above.").arg(pane.inspector.error)
                        : qsTr("Connect to a contact: the handshake, its records and its keys appear here as they happen. Ended sessions stay here for a while.")
                    role: "secondary"
                    wrapMode: Text.Wrap
                }
            }

            Spinner {
                anchors.centerIn: parent
                visible: pane.inspector.loading && pane.inspector.sessionId >= 0
                size: 28
            }
        }

        // -- what this trace can and cannot show ----------------------------------------------------
        Divider {
            Layout.fillWidth: true
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.margins: Theme.s3
            Layout.leftMargin: Theme.s4
            spacing: Theme.s2

            Icon {
                name: pane.inspector.exposure === "glass_box" ? "eye"
                    : pane.inspector.exposure === "lab" ? "flask-conical" : "lock"
                size: Theme.iconSize - 2
                color: pane.inspector.exposure === "glass_box" ? Theme.exposureText
                    : pane.inspector.exposure === "lab" ? Theme.labText : Theme.textSecondary
            }
            AppText {
                Layout.fillWidth: true
                objectName: "exposureNote"
                text: pane.inspector.exposure === "glass_box"
                    ? qsTr("Glass-box session: both sides can see and save its keys and messages.")
                    : pane.inspector.exposure === "lab"
                    ? qsTr("Lab: throwaway identities, every value revealed.")
                    : qsTr("Secret values are hidden in normal sessions.")
                role: "small"
                elide: Text.ElideRight
                color: pane.inspector.exposure === "glass_box" ? Theme.exposureText
                    : pane.inspector.exposure === "lab" ? Theme.labText : Theme.textSecondary
            }
            Tag {
                visible: !pane.inspector.following && pane.inspector.sessionId >= 0
                objectName: "pausedTag"
                text: qsTr("DISPLAY PAUSED")
                iconName: "pause"
            }
        }
    }

    Component {
        id: timelineView
        TimelineView {
            inspector: pane.inspector
        }
    }
    Component {
        id: messagesView
        MessagesView {
            inspector: pane.inspector
        }
    }
    Component {
        id: keysView
        KeysView {
            inspector: pane.inspector
        }
    }
    Component {
        id: securityView
        SecurityView {
            inspector: pane.inspector
        }
    }
}
