import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme

// A modal dialog: focus moves inside, Escape closes it unless the decision must be made with a
// button, and focus returns to the invoker afterwards (UI_DESIGN §5).
T.Dialog {
    id: control

    property string titleText
    property string iconName
    property color iconColor: Theme.text
    property int preferredWidth: 460
    // Receives keyboard focus as soon as the dialog shows (not after its open animation, or
    // early keystrokes would land in whatever had focus behind it).
    property Item initialFocus: null
    default property alias content: body.data
    property alias actions: actionRow.data

    function focusInitial() {
        if (initialFocus && initialFocus.visible && initialFocus.enabled)
            initialFocus.forceActiveFocus(Qt.PopupFocusReason)
        else
            contentItem.forceActiveFocus(Qt.PopupFocusReason)
    }

    onAboutToShow: Qt.callLater(focusInitial)

    parent: T.Overlay.overlay
    anchors.centerIn: parent
    modal: true
    focus: true
    implicitWidth: preferredWidth
    implicitHeight: contentHeight + topPadding + bottomPadding
        + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
        + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0)
    width: Math.min(preferredWidth, parent ? parent.width - Theme.s4 * 2 : preferredWidth)
    height: Math.min(implicitHeight, parent ? parent.height - Theme.s4 * 2 : implicitHeight)
    padding: Theme.s6
    topPadding: Theme.s4
    // The body reaches into the padding by the scroll bar's gutter (see contentItem).
    rightPadding: Theme.s6 - Theme.scrollGutter
    spacing: 0
    closePolicy: T.Popup.CloseOnEscape

    T.Overlay.modal: Rectangle {
        color: Theme.scrim

        Behavior on opacity {
            NumberAnimation { duration: Theme.motionFast }
        }
    }

    enter: Transition {
        NumberAnimation { property: "opacity"; from: 0; to: 1; duration: Theme.motionFast }
        NumberAnimation { property: "scale"; from: 0.98; to: 1; duration: Theme.motionFast; easing.type: Easing.OutCubic }
    }
    exit: Transition {
        NumberAnimation { property: "opacity"; from: 1; to: 0; duration: Theme.motionFast }
    }

    background: Rectangle {
        color: Theme.surface
        radius: Theme.radiusCard
        border.width: 1
        border.color: Theme.divider
    }

    header: Item {
        implicitHeight: control.titleText ? titleRow.implicitHeight + Theme.s6 : 0
        visible: control.titleText !== ""

        RowLayout {
            id: titleRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.leftMargin: Theme.s6
            anchors.rightMargin: Theme.s6
            spacing: Theme.s3

            Icon {
                visible: control.iconName !== ""
                name: control.iconName
                color: control.iconColor
                size: Theme.iconSize + 4
            }
            AppText {
                Layout.fillWidth: true
                text: control.titleText
                role: "title"
                wrapMode: Text.Wrap
                Accessible.role: Accessible.Heading
            }
        }
    }

    contentItem: Flickable {
        id: flick
        implicitWidth: body.implicitWidth
        implicitHeight: body.implicitHeight
        contentWidth: width
        contentHeight: body.implicitHeight
        clip: contentHeight > height
        boundsBehavior: Flickable.StopAtBounds
        T.ScrollBar.vertical: AppScrollBar {}

        ColumnLayout {
            id: body
            width: flick.width - Theme.scrollGutter
            spacing: Theme.s4
        }
    }

    footer: Item {
        implicitHeight: actionRow.children.length > 0 ? actionRow.implicitHeight + Theme.s6 : 0
        visible: actionRow.children.length > 0

        Flow {
            id: actionRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.leftMargin: Theme.s6
            anchors.rightMargin: Theme.s6
            layoutDirection: Qt.RightToLeft
            spacing: Theme.s2
        }
    }
}
