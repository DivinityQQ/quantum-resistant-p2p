import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Keys: the key schedule as a graph or as a dependency list (the same content as text), beside
// the selected node's derivation and state (UI_DESIGN §7.4).
Item {
    id: view

    required property var inspector
    property string mode: "graph"
    readonly property bool wide: width >= 860 * Math.max(1, Theme.scale)

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // How to read it: the mode, and what each node style means.
        Flow {
            Layout.fillWidth: true
            Layout.margins: Theme.s3
            spacing: Theme.s4

            SegmentedControl {
                label: qsTr("Show the key schedule as")
                current: view.mode
                options: [
                    { value: "graph", label: qsTr("Graph") },
                    { value: "list", label: qsTr("List") }
                ]
                onChosen: value => view.mode = value
            }
            Repeater {
                model: [
                    { style: "observed", label: qsTr("Derived (observed)") },
                    { style: "revealed", label: qsTr("Value available") },
                    { style: "spec", label: qsTr("Specification only") },
                    { style: "hash", label: qsTr("Transcript hash") }
                ]

                Row {
                    id: sample

                    required property var modelData

                    height: Theme.controlHeight
                    spacing: Theme.s2
                    visible: modelData.style !== "revealed" || view.inspector.exposure !== "public"

                    Item {
                        width: 28
                        height: 16
                        anchors.verticalCenter: parent.verticalCenter

                        Rectangle {
                            anchors.fill: parent
                            visible: sample.modelData.style !== "spec"
                            radius: sample.modelData.style === "hash" ? height / 2 : Theme.radiusTight
                            color: sample.modelData.style === "revealed" ? Theme.exposureFill : Theme.surface
                            border.width: 1
                            border.color: sample.modelData.style === "revealed" ? Theme.exposureText : Theme.controlBoundary
                        }
                        Shape {
                            anchors.fill: parent
                            visible: sample.modelData.style === "spec"
                            preferredRendererType: Shape.CurveRenderer

                            ShapePath {
                                strokeColor: Theme.controlBoundary
                                strokeWidth: 1
                                strokeStyle: ShapePath.DashLine
                                dashPattern: [3, 3]
                                fillColor: "transparent"
                                PathRectangle { x: 0.5; y: 0.5; width: 27; height: 15; radius: Theme.radiusTight }
                            }
                        }
                    }
                    AppText {
                        anchors.verticalCenter: parent.verticalCenter
                        text: sample.modelData.label
                        role: "small"
                    }
                }
            }
        }
        Divider {
            Layout.fillWidth: true
        }

        GridLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            columns: view.wide ? 3 : 1
            rowSpacing: 0
            columnSpacing: 0

            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredHeight: view.wide ? -1 : Math.round(view.height * 0.5)

                // Through a layer: its texture is the pane's size, so the edges are clipped with
                // every scene-graph backend (the software one does not clip shapes).
                Item {
                    anchors.fill: parent
                    visible: view.mode === "graph"
                    layer.enabled: visible

                    KeyGraph {
                        anchors.fill: parent
                        inspector: view.inspector
                    }
                }
                ListView {
                    id: list

                    objectName: "dependencyList"
                    anchors.fill: parent
                    visible: view.mode === "list"
                    model: view.inspector.keyNodes
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    keyNavigationEnabled: false
                    activeFocusOnTab: visible
                    function selected() { return view.inspector.keyNodes.indexOf(view.inspector.selectedNode) }
                    highlightMoveDuration: 0
                    T.ScrollBar.vertical: AppScrollBar {
                        id: bar
                    }
                    Accessible.role: Accessible.List
                    Accessible.name: qsTr("Key schedule dependencies")

                    function step(delta) {
                        if (count === 0)
                            return
                        const current = selected()
        const from = current < 0 ? (delta > 0 ? -1 : count) : current
                        const next = Math.max(0, Math.min(count - 1, from + delta))
                        view.inspector.selectNode(view.inspector.keyNodes.get(next).key)
                        positionViewAtIndex(next, ListView.Contain)
                    }
                    Keys.onUpPressed: step(-1)
                    Keys.onDownPressed: step(1)

                    FocusRing {
                        visible: list.activeFocus
                        anchors.margins: 0
                        cornerRadius: 0
                    }

                    delegate: T.ItemDelegate {
                        id: entry

                        required property var model
                        required property string key
                        required property string inputs
                        required property int epoch
                        readonly property bool selected: key === view.inspector.selectedNode

                        width: list.width - bar.gutter
                        implicitHeight: lines.implicitHeight + Theme.s2 * 2
                        leftPadding: Theme.s3
                        rightPadding: Theme.s3
                        hoverEnabled: true
                        focusPolicy: Qt.NoFocus
                        Accessible.role: Accessible.ListItem
                        Accessible.name: key + (inputs !== "" ? qsTr(", from %1").arg(inputs) : "") + ", " + model.state
                        Accessible.selected: selected

                        onClicked: {
                            list.forceActiveFocus()
                            view.inspector.selectNode(key)
                        }

                        contentItem: ColumnLayout {
                            id: lines
                            spacing: 0

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.s2

                                AppText {
                                    Layout.fillWidth: true
                                    text: entry.key
                                    role: "mono"
                                    elide: Text.ElideRight
                                    color: entry.selected ? Theme.selectionText : Theme.text
                                }
                                Tag {
                                    visible: entry.model.state !== "observed"
                                    text: entry.model.state === "revealed" ? qsTr("VALUE")
                                        : entry.model.state === "spec" ? qsTr("SPEC ONLY") : qsTr("UNAVAILABLE")
                                    kind: entry.model.state === "revealed" ? "exposure" : "neutral"
                                }
                                AppText {
                                    text: qsTr("epoch %1").arg(entry.epoch)
                                    role: "small"
                                }
                            }
                            AppText {
                                Layout.fillWidth: true
                                visible: entry.inputs !== ""
                                text: "← " + entry.inputs
                                role: "small"
                                elide: Text.ElideRight
                                color: entry.selected ? Theme.selectionText : Theme.textSecondary
                            }
                        }
                        background: Rectangle {
                            color: entry.selected ? Theme.selectionFill : entry.hovered ? Theme.hoverFill : "transparent"
                        }
                    }
                }
                AppText {
                    anchors.centerIn: parent
                    width: Math.min(parent.width - Theme.s6 * 2, 420)
                    visible: view.inspector.keyNodes.count === 0
                    horizontalAlignment: Text.AlignHCenter
                    text: qsTr("No keys derived yet: the schedule appears as the handshake runs.")
                    role: "secondary"
                    wrapMode: Text.Wrap
                }
            }

            Divider {
                vertical: view.wide
                Layout.fillWidth: !view.wide
                Layout.fillHeight: view.wide
            }

            NodeDetail {
                Layout.preferredWidth: view.wide ? Math.max(300, Math.round(view.width * 0.34)) : -1
                Layout.fillWidth: !view.wide
                Layout.fillHeight: true
                Layout.margins: Theme.s4
                inspector: view.inspector
            }
        }
    }
}
