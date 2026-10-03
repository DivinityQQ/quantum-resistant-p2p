import QtQuick
import QtQuick.Shapes
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// The key schedule as a dependency graph: each secret or transcript hash is a box, each edge an
// input of the specification's derivation. A selected node's inputs and outputs are drawn
// strongly and every other edge dims. Keyboard: Up and Down walk the nodes in order, Left goes
// to the first input, Right to the first output, Escape clears the selection.
Flickable {
    id: graph

    required property var inspector
    readonly property int boxWidth: Math.ceil(metrics.advanceWidth * 13) + Theme.s3 * 2
    readonly property int boxHeight: Math.round(Theme.sizeMono * 2.2)
    readonly property int columnWidth: boxWidth + Theme.s8
    readonly property int rowHeight: boxHeight + Theme.s3
    readonly property int margin: Theme.s4

    objectName: "keyGraph"
    clip: true
    contentWidth: inspector.keyColumns * columnWidth + margin * 2
    contentHeight: inspector.keyRows * rowHeight + margin * 2
    boundsBehavior: Flickable.StopAtBounds
    activeFocusOnTab: true
    T.ScrollBar.vertical: AppScrollBar {}
    T.ScrollBar.horizontal: AppScrollBar {}
    Accessible.role: Accessible.Graphic
    Accessible.name: qsTr("Key schedule graph, %n nodes; the dependency list has the same content", "", inspector.keyNodes.count)

    function nodeAt(delta) {
        const nodes = inspector.keyNodes
        if (nodes.count === 0)
            return
        const current = nodes.indexOf(inspector.selectedNode)
        const from = current < 0 ? (delta > 0 ? -1 : nodes.count) : current
        select(nodes.get(Math.max(0, Math.min(nodes.count - 1, from + delta))).key)
    }
    function follow(field) {
        const nodes = inspector.keyNodes
        const current = nodes.indexOf(inspector.selectedNode)
        if (current < 0)
            return
        const names = nodes.get(current)[field]
        if (names !== "")
            select(names.split(", ")[0])
    }
    function select(key) {
        inspector.selectNode(key)
        reveal(key)
    }
    // Scroll a node into view, unless it already is.
    function reveal(key) {
        const index = inspector.keyNodes.indexOf(key)
        if (index < 0)
            return
        const node = inspector.keyNodes.get(index)
        const x = margin + node.column * columnWidth
        const y = margin + node.row * rowHeight
        contentX = Math.max(0, Math.min(x - Theme.s4, Math.max(contentX, x + boxWidth + Theme.s4 - width)))
        contentY = Math.max(0, Math.min(y - Theme.s4, Math.max(contentY, y + boxHeight + Theme.s4 - height)))
    }
    Keys.onUpPressed: nodeAt(-1)
    Keys.onDownPressed: nodeAt(1)
    Keys.onLeftPressed: follow("inputs")
    Keys.onRightPressed: follow("outputs")
    Keys.onEscapePressed: inspector.selectNode("")
    Component.onCompleted: if (inspector.selectedNode !== "") reveal(inspector.selectedNode)

    // A node chosen elsewhere (an input in the detail, the dependency list) comes into view.
    Connections {
        target: graph.inspector
        function onSelectionChanged() {
            if (graph.inspector.selectedNode !== "")
                graph.reveal(graph.inspector.selectedNode)
        }
    }

    TextMetrics {
        id: metrics
        font.family: Theme.monoFamily
        font.pixelSize: Theme.sizeMono
        text: "0"
    }

    // Edges under the nodes: from the right side of an input to the left side of its output.
    Repeater {
        model: graph.inspector.keyEdges

        Shape {
            id: edge

            required property string source
            required property string target
            required property int fromColumn
            required property int fromRow
            required property int toColumn
            required property int toRow
            readonly property string chosen: graph.inspector.selectedNode
            readonly property bool related: chosen !== "" && (source === chosen || target === chosen)
            readonly property real x0: graph.margin + fromColumn * graph.columnWidth + graph.boxWidth
            readonly property real y0: graph.margin + fromRow * graph.rowHeight + graph.boxHeight / 2
            readonly property real x1: graph.margin + toColumn * graph.columnWidth
            readonly property real y1: graph.margin + toRow * graph.rowHeight + graph.boxHeight / 2
            readonly property real bend: Math.max(36, (x1 - x0) / 2)

            width: graph.contentWidth
            height: graph.contentHeight
            z: related ? 1 : 0
            preferredRendererType: Shape.CurveRenderer

            ShapePath {
                strokeColor: edge.related ? Theme.selectionText
                    : edge.chosen !== "" ? Theme.divider : Theme.controlBoundary
                strokeWidth: edge.related ? 2 : 1
                fillColor: "transparent"
                startX: edge.x0
                startY: edge.y0
                PathCubic {
                    x: edge.x1
                    y: edge.y1
                    control1X: edge.x0 + edge.bend
                    control1Y: edge.y0
                    control2X: edge.x1 - edge.bend
                    control2Y: edge.y1
                }
            }
        }
    }

    Repeater {
        model: graph.inspector.keyNodes

        Item {
            id: node

            required property var model
            required property string key
            required property string kind
            required property int column
            required property int row
            readonly property string status: model.state
            readonly property bool selected: key === graph.inspector.selectedNode
            readonly property bool dashed: status === "spec"

            x: graph.margin + column * graph.columnWidth
            y: graph.margin + row * graph.rowHeight
            z: 2
            width: graph.boxWidth
            height: graph.boxHeight
            Accessible.role: Accessible.Button
            Accessible.name: key + ", " + status

            Rectangle {
                anchors.fill: parent
                radius: node.kind === "hash" ? height / 2 : Theme.radiusTight + 2
                color: node.selected ? Theme.selectionFill
                    : node.status === "revealed" ? Theme.exposureFill
                    : node.status === "observed" ? Theme.surface
                    : Theme.canvas
                border.width: node.dashed ? 0 : node.selected ? 2 : 1
                border.color: node.selected ? Theme.selectionText
                    : node.status === "revealed" ? Theme.exposureText
                    : node.status === "observed" ? Theme.controlBoundary : Theme.divider
            }
            // A specification relationship is dashed: not reported in this trace.
            Shape {
                anchors.fill: parent
                visible: node.dashed && !node.selected
                preferredRendererType: Shape.CurveRenderer

                ShapePath {
                    strokeColor: Theme.controlBoundary
                    strokeWidth: 1
                    strokeStyle: ShapePath.DashLine
                    dashPattern: [3, 3]
                    fillColor: "transparent"
                    PathRectangle {
                        x: 0.5
                        y: 0.5
                        width: node.width - 1
                        height: node.height - 1
                        radius: node.kind === "hash" ? node.height / 2 : Theme.radiusTight + 2
                    }
                }
            }
            AppText {
                anchors.fill: parent
                anchors.leftMargin: Theme.s2
                anchors.rightMargin: Theme.s2
                verticalAlignment: Text.AlignVCenter
                horizontalAlignment: Text.AlignHCenter
                text: node.key
                role: "mono"
                elide: Text.ElideMiddle
                color: node.selected ? Theme.selectionText
                    : node.status === "revealed" ? Theme.exposureText
                    : node.status === "observed" ? Theme.text : Theme.textSecondary
            }
            TapHandler {
                onTapped: {
                    graph.forceActiveFocus()
                    graph.inspector.selectNode(node.key)
                }
            }
        }
    }

    FocusRing {
        parent: graph
        visible: graph.activeFocus
        anchors.margins: 0
        cornerRadius: 0
    }
}
