import QtQuick
import QtQuick.Layouts
import Qrp2p.Theme
import Qrp2p.Components
import Qrp2p.Inspector

// The unlocked app: header, contact strip and the selected conversation (UI_DESIGN §3). The
// Inspector opens beside the chat on wide windows, instead of it on narrow ones, and can be
// expanded over it (§3.3); the conversation and its draft stay as they were meanwhile.
Item {
    id: screen

    required property var app
    required property var workspace

    signal attention()

    property bool inspectorOpen: false
    property bool inspectorExpanded: false
    objectName: "messenger"
    readonly property bool split: width >= 1000

    onInspectorOpenChanged: {
        workspace.inspector.setOpen(inspectorOpen)
        if (!inspectorOpen) {
            inspectorExpanded = false
            if (conversationLoader.item && conversationLoader.item.focusComposer)
                conversationLoader.item.focusComposer()
        }
    }

    opacity: 0
    Component.onCompleted: opacity = 1
    Behavior on opacity {
        NumberAnimation { duration: Theme.motion }
    }

    Connections {
        target: screen.workspace
        function onNoticePosted(text) { toasts.show(text) }
        function onIncomingMessage(name) { screen.attention() }
        function onVerifyRequested(contactId) { verifyDialog.open() }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        HeaderBar {
            Layout.fillWidth: true
            app: screen.app
            workspace: screen.workspace
            inspectorOpen: screen.inspectorOpen
            onOpenChooser: chooser.openContacts()
            onOpenConnect: connectDialog.open()
            onOpenSettings: settingsDialog.open()
            onOpenShortcuts: shortcutsDialog.open()
            onToggleInspector: screen.inspectorOpen = !screen.inspectorOpen
        }
        ContactStrip {
            id: strip
            Layout.fillWidth: true
            workspace: screen.workspace
            visible: screen.workspace.contactCount > 0
            onOpenChooser: chooser.openContacts()
            onOpenConnect: chooser.openNearby()
        }
        Divider {
            Layout.fillWidth: true
        }
        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Item {
                id: chatPane
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                width: !screen.inspectorOpen ? parent.width
                    : screen.split && !screen.inspectorExpanded ? Math.max(320, Math.round(parent.width * 0.34)) : 0
                visible: width > 0
                clip: true

                Behavior on width {
                    enabled: !Theme.reducedMotion
                    NumberAnimation { duration: Theme.motion; easing.type: Easing.OutCubic }
                }

                Loader {
                    id: conversationLoader
                    anchors.fill: parent
                    property var current: screen.workspace.conversation
                    // A new view per conversation: the composer starts from that conversation's
                    // draft and the list from its end.
                    onCurrentChanged: {
                        active = false
                        active = true
                    }
                    sourceComponent: current ? conversationView : emptyView
                }
            }
            Loader {
                id: inspectorLoader
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.right: parent.right
                anchors.left: chatPane.right
                active: screen.inspectorOpen
                visible: active
                clip: true  // while the split opens, the pane is narrower than its contents
                // Opening moves focus to the active tab (UI_DESIGN §5).
                onLoaded: Qt.callLater(() => { if (item) item.focusTabs() })
                sourceComponent: InspectorPane {
                    inspector: screen.workspace.inspector
                    split: screen.split
                    expanded: screen.inspectorExpanded
                    canExpand: screen.split
                    onBackToChat: screen.inspectorOpen = false
                    onToggleExpanded: screen.inspectorExpanded = !screen.inspectorExpanded
                }
            }
        }
    }

    Component {
        id: conversationView

        ConversationView {
            conversation: conversationLoader.current
            onVerify: verifyDialog.open()
            onDetails: detailsDialog.open()
            onConfirm: action => confirmDialog.ask(action, conversationLoader.current)
            onRequestGlassBox: {
                glassBoxDialog.conversation = conversationLoader.current
                glassBoxDialog.open()
            }
            Component.onCompleted: focusComposer()
        }
    }

    Component {
        id: emptyView

        EmptyState {
            workspace: screen.workspace
            onFindNearby: chooser.openNearby()
            onEnterAddress: connectDialog.open()
        }
    }

    ContactChooser {
        id: chooser
        objectName: "chooser"
        workspace: screen.workspace
        x: Theme.s4
        y: 56 + Theme.s2
        onEnterAddress: connectDialog.open()
    }
    ConnectDialog {
        id: connectDialog
        objectName: "connectDialog"
        workspace: screen.workspace
    }
    PromptDialog {
        objectName: "promptDialog"
        prompts: screen.workspace.prompts
    }
    VerifyDialog {
        id: verifyDialog
        objectName: "verifyDialog"
        workspace: screen.workspace
        conversation: screen.workspace.conversation
    }
    ContactDetailsDialog {
        id: detailsDialog
        objectName: "detailsDialog"
        conversation: screen.workspace.conversation
        onVerify: verifyDialog.open()
        onConfirm: action => confirmDialog.ask(action, screen.workspace.conversation)
    }
    ConfirmDialog {
        id: confirmDialog
        objectName: "confirmDialog"
    }
    GlassBoxRequestDialog {
        id: glassBoxDialog
        objectName: "glassBoxDialog"
    }
    SettingsDialog {
        id: settingsDialog
        objectName: "settingsDialog"
        app: screen.app
        workspace: screen.workspace
    }
    WelcomeDialog {
        app: screen.app
        workspace: screen.workspace
    }
    ShortcutsDialog {
        id: shortcutsDialog
        objectName: "shortcutsDialog"
    }

    // Notices name contacts, so they live and die with the unlocked workspace: a lock takes
    // them away with everything else (UI_DESIGN §6.1).
    ToastHost {
        id: toasts
        objectName: "toasts"
    }

    Shortcut {
        sequence: "Ctrl+K"
        onActivated: chooser.openContacts()
    }
    Shortcut {
        sequence: "Ctrl+N"
        onActivated: connectDialog.open()
    }
    Shortcut {
        sequences: [StandardKey.Preferences, "Ctrl+,"]
        onActivated: settingsDialog.open()
    }
    Shortcut {
        sequence: "Ctrl+I"
        onActivated: screen.inspectorOpen = !screen.inspectorOpen
    }
}
