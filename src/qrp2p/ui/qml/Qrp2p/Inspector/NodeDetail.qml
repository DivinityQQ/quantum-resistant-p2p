import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// The selected secret or transcript hash: how the specification derives it, what this trace
// observed of it, and whether the engine has released it. A value appears only where the
// session revealed it (glass-box or lab) or where it is public (a transcript hash).
Flickable {
    id: detail

    required property var inspector
    readonly property var node: {
        const key = inspector.selectedNode
        const index = key !== "" ? inspector.keyNodes.indexOf(key) : -1
        return index >= 0 ? inspector.keyNodes.get(index) : null
    }

    clip: true
    contentHeight: column.implicitHeight
    boundsBehavior: Flickable.StopAtBounds
    T.ScrollBar.vertical: AppScrollBar {}

    ColumnLayout {
        id: column
        width: detail.width - Theme.scrollGutter
        spacing: Theme.s3

        AppText {
            Layout.fillWidth: true
            visible: detail.node === null
            text: qsTr("Select a key or transcript hash to see how it is derived and what this trace observed of it.")
            role: "secondary"
            wrapMode: Text.Wrap
        }

        ColumnLayout {
            Layout.fillWidth: true
            visible: detail.node !== null
            spacing: 2

            AppText {
                Layout.fillWidth: true
                text: detail.node ? detail.node.key : ""
                role: "title"
                font.family: Theme.monoFamily
                wrapMode: Text.WrapAnywhere
                Accessible.role: Accessible.Heading
            }
            AppText {
                Layout.fillWidth: true
                text: detail.node ? detail.describe(detail.node) : ""
                role: "secondary"
                wrapMode: Text.Wrap
            }
        }

        // How the specification derives it.
        Rectangle {
            Layout.fillWidth: true
            visible: detail.node !== null
            implicitHeight: operation.implicitHeight + Theme.s3 * 2
            radius: Theme.radiusControl
            color: Theme.surfaceSubtle

            AppText {
                id: operation
                anchors.fill: parent
                anchors.margins: Theme.s3
                text: detail.node ? detail.node.operation : ""
                role: "mono"
                wrapMode: Text.Wrap
            }
        }

        Repeater {
            model: detail.node ? [[qsTr("Inputs"), detail.node.inputs], [qsTr("Used by"), detail.node.outputs]] : []

            ColumnLayout {
                id: group

                required property var modelData

                Layout.fillWidth: true
                visible: modelData[1] !== ""
                spacing: Theme.s1

                AppText {
                    text: group.modelData[0]
                    role: "label"
                }
                Flow {
                    Layout.fillWidth: true
                    spacing: Theme.s1

                    Repeater {
                        model: group.modelData[1] !== "" ? group.modelData[1].split(", ") : []

                        AppButton {
                            required property string modelData
                            kind: "secondary"
                            compact: true
                            text: modelData
                            font.family: Theme.monoFamily
                            onClicked: detail.inspector.selectNode(modelData)
                        }
                    }
                }
            }
        }

        // The state this trace shows, in words: never by colour alone.
        ColumnLayout {
            Layout.fillWidth: true
            visible: detail.node !== null
            spacing: Theme.s1

            AppText {
                text: qsTr("In this trace")
                role: "label"
            }
            AppText {
                Layout.fillWidth: true
                text: detail.node ? detail.stateText(detail.node) : ""
                wrapMode: Text.Wrap
                color: detail.node && detail.node.state === "revealed" ? Theme.exposureText : Theme.text
            }
            AppText {
                Layout.fillWidth: true
                visible: detail.node !== null && detail.node.released !== ""
                text: detail.node ? detail.releasedText(detail.node) : ""
                role: "secondary"
                wrapMode: Text.Wrap
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            visible: detail.node !== null && detail.node.value !== ""
            spacing: Theme.s1

            RowLayout {
                Layout.fillWidth: true

                AppText {
                    Layout.fillWidth: true
                    text: detail.node && detail.node.kind === "hash" ? qsTr("Digest (public)") : qsTr("Value (revealed)")
                    role: "label"
                    color: detail.node && detail.node.kind === "hash" ? Theme.textSecondary : Theme.exposureText
                }
                AppButton {
                    kind: "quiet"
                    compact: true
                    iconName: "copy"
                    text: qsTr("Copy hex")
                    onClicked: detail.inspector.copyNodeValue(detail.node.key)
                }
            }
            AppText {
                Layout.fillWidth: true
                objectName: "nodeValue"
                text: detail.node ? detail.node.value : ""
                role: "mono"
                wrapMode: Text.WrapAnywhere
            }
        }

        RowLayout {
            visible: detail.node !== null
            spacing: Theme.s2

            AppButton {
                visible: detail.node !== null && detail.node.ordinal >= 0
                compact: true
                iconName: "clock"
                text: qsTr("Show the event")
                onClicked: detail.inspector.showOrdinal(detail.node.ordinal)
            }
            AppButton {
                visible: detail.node !== null && detail.node.section !== ""
                kind: "quiet"
                compact: true
                iconName: "external-link"
                text: detail.node ? detail.node.cite : ""
                toolTipText: qsTr("Open this section of the specification in your browser")
                onClicked: detail.inspector.openSpec(detail.node.section)
            }
        }
    }

    function describe(node) {
        const kinds = {
            kem: qsTr("KEM key or shared secret"),
            secret: qsTr("Secret"),
            key: qsTr("AEAD key or IV"),
            hash: qsTr("Transcript hash"),
            identity: qsTr("Identity private key seed")
        }
        const parts = [kinds[node.kind] || node.kind, qsTr("epoch %1").arg(node.epoch)]
        if (node.size > 0)
            parts.push(qsTr("%n bytes", "", node.size))
        return parts.join(" · ")
    }

    function stateText(node) {
        switch (node.state) {
        case "revealed":
            return inspector.exposure === "lab"
                ? qsTr("Value available in this lab trace.")
                : qsTr("Value available in this glass-box trace: both sides agreed to expose it.")
        case "observed":
            return node.kind === "hash"
                ? qsTr("Computed (observed). A transcript hash is public: its digest is shown.")
                : qsTr("Derived (observed): the engine reported deriving it. Its value is hidden in a normal session; there is no way to reveal it.")
        case "spec":
            return qsTr("Specification relationship: this trace did not report it (not reached yet, or before the first retained event).")
        default:
            return qsTr("No longer retained or unavailable.")
        }
    }

    function releasedText(node) {
        const when = {
            used: qsTr("after its last use"),
            replaced: qsTr("when the next key replaced it"),
            handshake_done: qsTr("when the handshake finished"),
            epoch_done: qsTr("when its epoch ended"),
            closed: qsTr("when the session closed")
        }
        let text = qsTr("Released by the engine %1: it dropped its references. That is not proof the memory was wiped.")
            .arg(when[node.released] || node.released)
        if (node.state === "revealed")
            text += " " + qsTr("This trace captured the value, so it stays visible here although the engine no longer holds it.")
        return text
    }
}
