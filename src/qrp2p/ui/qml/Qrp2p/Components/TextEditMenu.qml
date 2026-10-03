import QtQuick
import Qrp2p.Theme

// The context menu of a text field, text area or read-only text (right click or the menu key):
// attach it with `T.ContextMenu.menu: TextEditMenu { editor: ... }`. Read-only text offers only
// Copy, which copies the whole text when nothing is selected, and Select all. A masked password
// can be pasted into but never copied out. `paste` can be replaced (the composer sends copied
// files and images as files, and says so through `canPasteOther`).
AppMenu {
    id: menu

    required property Item editor
    property var paste: () => editor.paste()
    // Whether `paste` can use what the clipboard holds beyond text (asked as the menu opens).
    property var canPasteOther: () => false
    property bool _pasteOther: false

    readonly property bool editable: !editor.readOnly
    readonly property bool masked: editor.echoMode !== undefined && editor.echoMode !== TextInput.Normal
    readonly property bool hasSelection: editor.selectedText.length > 0

    function copyAll() {
        if (hasSelection) {
            editor.copy()
            return
        }
        editor.selectAll()
        editor.copy()
        editor.deselect()
    }

    onAboutToShow: _pasteOther = canPasteOther()

    // Focus goes back to the text, with its selection, when the menu closes.
    onClosed: if (editor.visible) editor.forceActiveFocus(Qt.PopupFocusReason)

    // The usual key for each entry, as the platform writes it. (A Shortcut's nativeText would
    // do, but Qt warns for keys with several bindings, such as Redo.)
    readonly property bool mac: Qt.platform.os === "osx"
    function keys(letter, shift) {
        if (mac)
            return (shift ? "\u21E7" : "") + "\u2318" + letter
        return "Ctrl+" + (shift ? "Shift+" : "") + letter
    }

    AppMenuItem {
        visible: menu.editable
        text: qsTr("Undo")
        shortcutText: menu.keys("Z", false)
        enabled: menu.editor.canUndo
        onTriggered: menu.editor.undo()
    }
    AppMenuItem {
        visible: menu.editable
        text: qsTr("Redo")
        shortcutText: Qt.platform.os === "windows" ? menu.keys("Y", false) : menu.keys("Z", true)
        enabled: menu.editor.canRedo
        onTriggered: menu.editor.redo()
    }
    AppMenuSeparator {
        visible: menu.editable
    }
    AppMenuItem {
        visible: menu.editable
        text: qsTr("Cut")
        shortcutText: menu.keys("X", false)
        enabled: menu.hasSelection && !menu.masked
        onTriggered: menu.editor.cut()
    }
    AppMenuItem {
        objectName: "menuCopy"
        text: qsTr("Copy")
        shortcutText: menu.keys("C", false)
        enabled: !menu.masked && (menu.hasSelection || (!menu.editable && menu.editor.length > 0))
        onTriggered: menu.editable ? menu.editor.copy() : menu.copyAll()
    }
    AppMenuItem {
        objectName: "menuPaste"
        visible: menu.editable
        text: qsTr("Paste")
        shortcutText: menu.keys("V", false)
        enabled: menu.editor.canPaste || menu._pasteOther
        onTriggered: menu.paste()
    }
    AppMenuSeparator {}
    AppMenuItem {
        text: qsTr("Select all")
        shortcutText: menu.keys("A", false)
        enabled: menu.editor.length > 0
        onTriggered: menu.editor.selectAll()
    }
}
