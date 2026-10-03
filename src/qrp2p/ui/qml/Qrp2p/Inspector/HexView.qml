import QtQuick
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Bytes as rows of 16, built only for the rows in view (a record frame is a thousand rows).
// The highlighted range is the selected field's, half-open; clicking a byte selects the
// innermost field holding it. The field table is the keyboard path to the same selection.
ListView {
    id: view

    required property var bytes        // a HexModel
    property string source: "frame"
    readonly property int cellWidth: Math.ceil(metrics.advanceWidth * 2) + Theme.s2
    readonly property bool showAscii: width >= offsetWidth + cellWidth * 16 + asciiWidth + Theme.s4 * 2
    readonly property int offsetWidth: Math.ceil(metrics.advanceWidth * 6) + Theme.s4
    readonly property int asciiWidth: Math.ceil(metrics.advanceWidth * 16) + Theme.s4

    signal byteClicked(int offset)

    model: bytes
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    flickableDirection: Flickable.AutoFlickDirection
    contentWidth: offsetWidth + cellWidth * 16 + (showAscii ? asciiWidth : 0)
    activeFocusOnTab: false
    reuseItems: true
    T.ScrollBar.vertical: AppScrollBar {}
    T.ScrollBar.horizontal: AppScrollBar {}
    Accessible.role: Accessible.Table
    Accessible.name: qsTr("%n bytes; the selected field's bytes are highlighted", "", bytes.size)

    TextMetrics {
        id: metrics
        font.family: Theme.monoFamily
        font.pixelSize: Theme.sizeMono
        text: "0"
    }

    // A newly selected field scrolls into view, unless it already is.
    Connections {
        target: view.bytes
        function onChanged() {
            if (view.bytes.highlightLength > 0)
                view.positionViewAtIndex(Math.floor(view.bytes.highlightStart / 16), ListView.Contain)
        }
    }

    delegate: Item {
        id: line

        required property string offset
        required property var cells
        required property string ascii
        required property int first

        width: view.contentWidth
        implicitHeight: Math.round(Theme.sizeMono * 1.7)

        AppText {
            width: view.offsetWidth
            anchors.verticalCenter: parent.verticalCenter
            text: line.offset
            role: "mono"
            color: Theme.textSecondary
            Accessible.ignored: true
        }
        Row {
            x: view.offsetWidth
            height: parent.height

            Repeater {
                model: line.cells

                Rectangle {
                    id: cell

                    required property string modelData
                    required property int index
                    readonly property int at: line.first + index
                    readonly property bool lit: at >= view.bytes.highlightStart
                        && at < view.bytes.highlightStart + view.bytes.highlightLength

                    width: view.cellWidth
                    height: parent.height
                    color: lit ? Theme.selectionFill : pointer.hovered ? Theme.hoverFill : "transparent"

                    AppText {
                        anchors.centerIn: parent
                        text: cell.modelData
                        role: "mono"
                        color: cell.lit ? Theme.selectionText : Theme.text
                    }
                    HoverHandler {
                        id: pointer
                    }
                    TapHandler {
                        onTapped: view.byteClicked(cell.at)
                    }
                }
            }
        }
        AppText {
            x: view.offsetWidth + view.cellWidth * 16 + Theme.s4
            anchors.verticalCenter: parent.verticalCenter
            visible: view.showAscii
            text: line.ascii
            role: "mono"
            color: Theme.textSecondary
            Accessible.ignored: true
        }
    }
}
