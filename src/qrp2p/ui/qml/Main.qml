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

    width: 1280
    height: 800
    minimumWidth: 720
    minimumHeight: 540
    visible: true
    title: "QRP2P"
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
        active: window.unlocked
        sourceComponent: MessengerScreen {
            app: window.app
            workspace: window.app.workspace
            onNotify: text => toasts.show(text)
            onAttention: if (!window.active) window.alert(0)
        }
    }

    ToastHost {
        id: toasts
    }

    Shortcut {
        sequence: "Ctrl+L"
        enabled: window.unlocked
        onActivated: window.app.lock()
    }
}
