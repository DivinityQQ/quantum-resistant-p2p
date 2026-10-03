import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// A popup menu; Escape closes it and returns focus to its button.
T.Menu {
    id: control

    implicitWidth: Math.max(220, contentItem.implicitWidth + leftPadding + rightPadding)
    implicitHeight: contentItem.implicitHeight + topPadding + bottomPadding
    padding: Theme.s1
    margins: Theme.s2
    overlap: 0
    modal: false
    focus: true

    delegate: AppMenuItem {}

    contentItem: ListView {
        implicitHeight: contentHeight
        implicitWidth: {
            let widest = 0
            for (let i = 0; i < count; ++i) {
                const item = itemAtIndex(i)
                if (item)
                    widest = Math.max(widest, item.implicitWidth)
            }
            return widest
        }
        model: control.contentModel
        interactive: Window.window ? contentHeight > Window.window.height : false
        clip: true
        currentIndex: control.currentIndex
    }

    background: Rectangle {
        color: Theme.surface
        radius: Theme.radiusControl + 2
        border.width: 1
        border.color: Theme.divider
    }
}
