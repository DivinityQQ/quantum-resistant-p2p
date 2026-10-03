import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Write and send. Enter sends, Shift+Enter starts a new line, and an input method's composition
// is never cut short (UI_DESIGN §6.3). The draft lives in memory only and is gone after a lock.
Rectangle {
    id: composer

    required property var conversation

    signal attach()

    readonly property int maxBytes: 16000
    readonly property int bytes: utf8Length(area.text)
    readonly property bool canSend: conversation.online && area.text.trim().length > 0 && bytes <= maxBytes

    function utf8Length(text) {
        let n = 0
        for (let i = 0; i < text.length; ++i) {
            const c = text.charCodeAt(i)
            if (c < 0x80) n += 1
            else if (c < 0x800) n += 2
            else if (c >= 0xD800 && c <= 0xDBFF) { n += 4; ++i }
            else n += 3
        }
        return n
    }

    function send() {
        if (!canSend)
            return
        if (conversation.send(area.text))
            area.clear()
    }

    function paste() {
        if (!conversation.pasteFiles())
            area.paste()
    }

    function focusInput() {
        area.forceActiveFocus()
    }

    implicitHeight: Math.max(Theme.controlHeight + Theme.s3 * 2, flick.implicitHeight + Theme.s2 * 2)
        + (counter.visible ? counter.height : 0)
    radius: Theme.radiusCard
    color: Theme.surface
    border.width: area.activeFocus ? 2 : 1
    border.color: area.activeFocus ? Theme.focus : Theme.controlBoundary

    Connections {
        target: composer.conversation
        function onDraftRestored(text) {
            if (area.text === "")
                area.text = text
        }
    }

    RowLayout {
        id: row
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.leftMargin: Theme.s2
        anchors.rightMargin: Theme.s2
        anchors.topMargin: Theme.s2
        height: parent.height - Theme.s2 * 2 - (counter.visible ? counter.height : 0)
        spacing: Theme.s2

        IconButton {
            Layout.alignment: Qt.AlignBottom
            Layout.bottomMargin: (Theme.controlHeight + Theme.s1 - height) / 2
            label: qsTr("Send a file")
            iconName: "paperclip"
            enabled: composer.conversation.online
            onClicked: composer.attach()
        }
        Divider {
            vertical: true
            Layout.preferredHeight: Theme.controlHeight - Theme.s3
            Layout.alignment: Qt.AlignBottom
            Layout.bottomMargin: Theme.s2 + 2
        }
        Flickable {
            id: flick
            Layout.fillWidth: true
            Layout.fillHeight: true
            // Grows with its text up to six lines, then scrolls.
            implicitHeight: Math.min(area.implicitHeight,
                Math.ceil(metrics.lineSpacing * 6) + area.topPadding + area.bottomPadding)
            contentWidth: width
            contentHeight: area.implicitHeight
            boundsBehavior: Flickable.StopAtBounds
            clip: true
            T.ScrollBar.vertical: AppScrollBar {}

            FontMetrics {
                id: metrics
                font: area.font
            }

            T.TextArea.flickable: T.TextArea {
                id: area
                objectName: "composerInput"
                // The template has no implicit size (Qt's styles add it): without one the
                // composer never grows with its lines.
                implicitWidth: contentWidth + leftPadding + rightPadding
                implicitHeight: contentHeight + topPadding + bottomPadding
                textFormat: TextEdit.PlainText
                wrapMode: TextEdit.Wrap
                font.family: Theme.family
                font.pixelSize: Theme.sizeBody
                color: Theme.text
                selectionColor: Theme.selectionFill
                selectedTextColor: Theme.selectionText
                selectByMouse: true
                persistentSelection: false
                topPadding: Theme.s2 + 1
                bottomPadding: Theme.s2 + 1
                leftPadding: Theme.s1
                rightPadding: Theme.scrollGutter  // the scroll bar's room, also while hidden
                focus: true
                Accessible.name: qsTr("Message to %1").arg(composer.conversation.name)
                Accessible.description: qsTr("Enter sends; Shift+Enter starts a new line.")

                onTextChanged: composer.conversation.setDraft(text)
                Component.onCompleted: text = composer.conversation.draft

                // Copied files and images are offered as files; text is pasted as usual.
                T.ContextMenu.menu: TextEditMenu {
                    editor: area
                    paste: () => composer.paste()
                    canPasteOther: () => composer.conversation.clipboardHasFiles()
                }
                Keys.onPressed: event => {
                    if (event.matches(StandardKey.Paste) && composer.conversation.pasteFiles())
                        event.accepted = true
                }

                Keys.onReturnPressed: event => composer.handleReturn(event)
                Keys.onEnterPressed: event => composer.handleReturn(event)

                AppText {
                    x: area.leftPadding
                    y: area.topPadding
                    width: area.width - area.leftPadding - area.rightPadding
                    text: composer.conversation.online
                        ? qsTr("Message %1…").arg(Theme.isolate(composer.conversation.name))
                        : qsTr("%1 is offline: connect to send").arg(Theme.isolate(composer.conversation.name))
                    color: Theme.textSecondary
                    elide: Text.ElideRight
                    visible: area.length === 0 && area.preeditText === ""
                }
            }
        }
        AppButton {
            objectName: "sendButton"
            Layout.alignment: Qt.AlignBottom
            Layout.bottomMargin: (Theme.controlHeight + Theme.s1 - height) / 2
            kind: "primary"
            text: qsTr("Send")
            enabled: composer.canSend
            toolTipText: qsTr("Send (Enter). New line: Shift+Enter")
            onClicked: composer.send()
        }
    }

    AppText {
        id: counter
        visible: composer.bytes > composer.maxBytes - 2000
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.rightMargin: Theme.s4
        anchors.bottomMargin: Theme.s1
        role: "small"
        color: composer.bytes > composer.maxBytes ? Theme.dangerText : Theme.textSecondary
        text: qsTr("%1 of %2 bytes").arg(composer.bytes.toLocaleString(Qt.locale(), "f", 0))
            .arg(composer.maxBytes.toLocaleString(Qt.locale(), "f", 0))
    }

    function handleReturn(event) {
        if ((event.modifiers & Qt.ShiftModifier) || area.inputMethodComposing) {
            event.accepted = false
            return
        }
        event.accepted = true
        send()
    }
}
