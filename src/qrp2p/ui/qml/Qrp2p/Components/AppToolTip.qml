import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme

// A themed tooltip. Tooltips supplement visible content; they never carry the only explanation
// of exposure or of a dangerous action (UI_DESIGN §5).
T.ToolTip {
    id: control

    // The template has no position: without one the tooltip covers its own control and takes
    // its clicks. Above and centred, as in Qt's styles; Qt flips it below at the window edge.
    x: parent ? Math.round((parent.width - width) / 2) : 0
    y: -height - Theme.s1
    delay: 600
    timeout: 8000
    margins: Theme.s2
    padding: Theme.s2
    leftPadding: Theme.s3
    rightPadding: Theme.s3
    implicitWidth: Math.min(contentItem.implicitWidth + leftPadding + rightPadding, 360)
    implicitHeight: contentItem.implicitHeight + topPadding + bottomPadding
    closePolicy: T.Popup.CloseOnEscape | T.Popup.CloseOnPressOutsideParent | T.Popup.CloseOnReleaseOutsideParent

    contentItem: AppText {
        text: control.text
        role: "small"
        color: Theme.primaryText
        wrapMode: Text.Wrap
    }
    background: Rectangle {
        color: Theme.primaryFill
        radius: Theme.radiusTight + 2
    }
}
