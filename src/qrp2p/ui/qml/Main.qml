import QtQuick
import QtQuick.Controls.Basic
import Qrp2p.Theme
import Qrp2p.Components
import Qrp2p.Screens

// The window. Before unlock it shows the unlock screen; after, the messenger. Locking unloads
// the messenger at once, with every view of conversations, drafts and prompts in it.
ApplicationWindow {
    id: window

    required property var app
    required property string monoFamily

    readonly property bool unlocked: app.phase === "unlocked" && app.workspace !== null
    // The workspace the messenger shows: replaced at each unlock and never set to null, so a
    // messenger being torn down at lock never sees its workspace vanish underneath it.
    property var workspaceView: null
    Binding on workspaceView {
        when: window.app.workspace !== null
        value: window.app.workspace
        restoreMode: Binding.RestoreNone
    }

    width: 1280
    height: 800
    minimumWidth: 720
    minimumHeight: 540
    visible: true
    // Unread messages show in the title (taskbar, window switcher) while unlocked; never names.
    title: app.unread > 0 ? qsTr("QRP2P (%1)").arg(app.unread) : "QRP2P"
    color: Theme.canvas
    font.family: Theme.family
    font.pixelSize: Theme.sizeBody

    Binding { target: Theme; property: "preference"; value: window.app.appearance }
    Binding { target: Theme; property: "reducedMotion"; value: window.app.reducedMotion }
    Binding { target: Theme; property: "textScale"; value: window.app.textScale }
    Binding { target: Theme; property: "monoFamily"; value: window.monoFamily }

    onActiveChanged: if (app.workspace) app.workspace.setWindowActive(active)

    Loader {
        anchors.fill: parent
        active: !window.unlocked
        sourceComponent: UnlockScreen {
            app: window.app
        }
    }

    Loader {
        id: messenger
        anchors.fill: parent
        active: window.unlocked && window.workspaceView === window.app.workspace
        sourceComponent: MessengerScreen {
            app: window.app
            workspace: window.workspaceView
            onAttention: if (!window.active) window.alert(0)
        }
    }

    Shortcut {
        sequence: "Ctrl+L"
        enabled: window.unlocked
        onActivated: window.app.lock()
    }
}
