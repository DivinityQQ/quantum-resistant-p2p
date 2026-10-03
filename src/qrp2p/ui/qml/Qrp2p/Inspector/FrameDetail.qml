import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// One captured frame: its fields, the selected field's explanation, and its bytes. The field,
// its highlighted bytes and the explanation always describe the same range (UI_DESIGN §2.3).
// Where the pane is short, the whole detail scrolls and the bytes keep a usable height.
Flickable {
    id: detail

    required property var inspector
    readonly property var field: row(inspector.selectedField)
    readonly property bool hasPlaintext: inspector.plaintext.size > 0
    property bool showPlaintext: false

    clip: true
    contentWidth: width
    contentHeight: Math.max(height, content.implicitHeight)
    boundsBehavior: Flickable.StopAtBounds
    T.ScrollBar.vertical: AppScrollBar {}

    // A byte count as the view model writes them ("9,155"), so both read alike.
    function count(n) {
        return Number(n).toLocaleString(Qt.locale("en_US"), "f", 0)
    }

    // The field row with this key, or null.
    function row(key) {
        const index = key !== "" ? inspector.fields.indexOf(key) : -1
        return index >= 0 ? inspector.fields.get(index) : null
    }

    Connections {
        target: detail.inspector
        function onSelectionChanged() { detail.followField() }
    }
    Component.onCompleted: followField()

    // The bytes shown follow the selected field: a decrypted field shows the plaintext.
    function followField() {
        const field = row(inspector.selectedField)
        showPlaintext = inspector.plaintext.size > 0 && field !== null && field.source === "plaintext"
    }

    ColumnLayout {
        id: content
        width: detail.width - Theme.scrollGutter
        height: detail.contentHeight
        spacing: Theme.s3

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2

            AppText {
                Layout.fillWidth: true
                objectName: "frameTitle"
                text: detail.inspector.frameTitle
                role: "title"
                elide: Text.ElideRight
                Accessible.role: Accessible.Heading
            }
            AppText {
                Layout.fillWidth: true
                text: detail.inspector.frameDetail
                role: "secondary"
                wrapMode: Text.Wrap
            }
        }

        FieldTable {
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(contentHeight, Math.max(140, detail.height * 0.36))
            Layout.minimumHeight: Math.min(contentHeight, 120)
            inspector: detail.inspector
        }

        // The selected field: what it is, where its bytes are, and its source.
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: about.implicitHeight + Theme.s3 * 2
            radius: Theme.radiusControl
            color: Theme.surfaceSubtle

            ColumnLayout {
                id: about
                anchors.fill: parent
                anchors.margins: Theme.s3
                spacing: Theme.s1

                AppText {
                    Layout.fillWidth: true
                    visible: detail.field === null
                    text: qsTr("Select a field to highlight its bytes and see what it is.")
                    role: "secondary"
                    wrapMode: Text.Wrap
                }
                RowLayout {
                    Layout.fillWidth: true
                    visible: detail.field !== null
                    spacing: Theme.s2

                    AppText {
                        text: detail.field ? detail.field.name : ""
                        font.weight: Theme.weightMedium
                    }
                    AppText {
                        Layout.fillWidth: true
                        text: {
                            const f = detail.field
                            if (!f)
                                return ""
                            if (f.length === 0 && f.source === "plaintext")
                                return qsTr("a decoded value, without a byte range of its own")
                            const where = f.source === "plaintext" ? qsTr("plaintext") : qsTr("frame")
                            return qsTr("%1 bytes · %2 [%3, %4)").arg(detail.count(f.length))
                                .arg(where).arg(f.start).arg(f.start + f.length)
                        }
                        role: "small"
                        elide: Text.ElideRight
                    }
                    AppButton {
                        kind: "quiet"
                        compact: true
                        iconName: "copy"
                        text: qsTr("Copy hex")
                        enabled: detail.field !== null && detail.field.length > 0
                        onClicked: detail.inspector.copyField(detail.inspector.selectedField)
                    }
                }
                AppText {
                    Layout.fillWidth: true
                    visible: detail.field !== null && detail.field.value !== ""
                    text: detail.field ? detail.field.value : ""
                    role: "mono"
                    wrapMode: Text.WrapAnywhere
                    maximumLineCount: 3
                    elide: Text.ElideRight
                }
                AppText {
                    Layout.fillWidth: true
                    visible: detail.field !== null && detail.field.explanation !== ""
                    text: detail.field ? detail.field.explanation : ""
                    wrapMode: Text.Wrap
                }
                RowLayout {
                    Layout.fillWidth: true
                    visible: detail.field !== null
                    spacing: Theme.s2

                    AppText {
                        Layout.fillWidth: true
                        text: detail.field ? detail.field.origin : ""
                        role: "small"
                        color: detail.field && detail.field.source === "plaintext" ? Theme.exposureText : Theme.textSecondary
                        elide: Text.ElideRight
                    }
                    AppButton {
                        kind: "quiet"
                        compact: true
                        visible: detail.field !== null && detail.field.section !== ""
                        iconName: "external-link"
                        text: detail.field ? detail.inspector.cite(detail.field.section) : ""
                        toolTipText: qsTr("Open this section of the specification in your browser")
                        onClicked: detail.inspector.openSpec(detail.field.section)
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.s2

            AppText {
                text: detail.showPlaintext ? qsTr("Decrypted bytes") : qsTr("Frame bytes")
                role: "label"
                color: detail.showPlaintext ? Theme.exposureText : Theme.textSecondary
            }
            AppText {
                Layout.fillWidth: true
                text: detail.showPlaintext
                    ? qsTr("offset within the plaintext · %1 bytes").arg(detail.count(detail.inspector.plaintext.size))
                    : qsTr("frame offset, header included · %1 bytes").arg(detail.count(detail.inspector.hex.size))
                role: "small"
                elide: Text.ElideRight
            }
            SegmentedControl {
                visible: detail.hasPlaintext
                label: qsTr("Bytes shown")
                current: detail.showPlaintext ? "plaintext" : "frame"
                options: [
                    { value: "frame", label: qsTr("Frame") },
                    { value: "plaintext", label: qsTr("Decrypted") }
                ]
                onChosen: value => detail.showPlaintext = value === "plaintext"
            }
        }

        HexView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.minimumHeight: Math.round(Theme.sizeMono * 1.7) * 6
            bytes: detail.showPlaintext ? detail.inspector.plaintext : detail.inspector.hex
            source: detail.showPlaintext ? "plaintext" : "frame"
            onByteClicked: offset => detail.inspector.selectByte(source, offset)
        }
    }
}
