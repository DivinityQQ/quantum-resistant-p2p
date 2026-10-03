import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// Security: the session's facts, each with its evidence and the assumption it rests on. No
// score: a fact is observed or it is not (UI_DESIGN §7.5).
ListView {
    id: view

    required property var inspector
    readonly property int column: Math.min(width - Theme.s6 * 2, Theme.readingWidth)

    objectName: "securityFacts"
    model: inspector.facts
    clip: true
    spacing: Theme.s3
    boundsBehavior: Flickable.StopAtBounds
    T.ScrollBar.vertical: AppScrollBar {
        id: bar
    }
    Accessible.role: Accessible.List
    Accessible.name: qsTr("Session security facts")

    header: Item {
        width: view.width
        height: Theme.s4
    }
    footer: Item {
        width: view.width
        height: closing.implicitHeight + Theme.s6 * 2

        AppText {
            id: closing
            x: Math.round((view.width - view.column) / 2)
            y: Theme.s6
            width: view.column
            text: qsTr("These facts describe this session as observed. A session that worked does not show that the protocol resists every attack, and it does not replace an outside review.")
            role: "small"
            wrapMode: Text.Wrap
        }
    }

    delegate: Item {
        id: fact

        required property string title
        required property string value
        required property string status
        required property string evidence
        required property string assumption
        required property int ordinal
        required property string section
        required property string cite

        width: view.width - bar.gutter
        implicitHeight: card.implicitHeight
        Accessible.role: Accessible.ListItem
        Accessible.name: title + ": " + value

        Rectangle {
            id: card
            x: Math.round((view.width - view.column) / 2)
            width: view.column
            implicitHeight: body.implicitHeight + Theme.s4 * 2
            radius: Theme.radiusCard
            color: fact.status === "danger" ? Theme.dangerFill : Theme.surface
            border.width: 1
            border.color: Theme.divider

            RowLayout {
                id: body
                anchors.fill: parent
                anchors.margins: Theme.s4
                spacing: Theme.s3

                Icon {
                    Layout.alignment: Qt.AlignTop
                    name: fact.status === "ok" ? "shield-check"
                        : fact.status === "warn" ? "triangle-alert"
                        : fact.status === "danger" ? "shield-alert" : "info"
                    color: fact.status === "ok" ? Theme.success
                        : fact.status === "warn" ? Theme.exposureText
                        : fact.status === "danger" ? Theme.dangerText : Theme.textSecondary
                    Accessible.ignored: false
                    Accessible.name: fact.status === "ok" ? qsTr("Holds")
                        : fact.status === "warn" ? qsTr("Caution")
                        : fact.status === "danger" ? qsTr("Failed") : qsTr("Information")
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: Theme.s1

                    AppText {
                        Layout.fillWidth: true
                        text: fact.title
                        role: "label"
                    }
                    AppText {
                        Layout.fillWidth: true
                        text: fact.value
                        font.weight: Theme.weightMedium
                        wrapMode: Text.Wrap
                        color: fact.status === "danger" ? Theme.dangerText : Theme.text
                    }
                    AppText {
                        Layout.fillWidth: true
                        visible: fact.evidence !== ""
                        text: fact.evidence
                        role: "secondary"
                        wrapMode: Text.Wrap
                    }
                    AppText {
                        Layout.fillWidth: true
                        visible: fact.assumption !== ""
                        text: qsTr("Assumes: %1").arg(fact.assumption)
                        role: "small"
                        wrapMode: Text.Wrap
                    }
                    RowLayout {
                        spacing: Theme.s2

                        AppButton {
                            visible: fact.ordinal >= 0
                            kind: "secondary"
                            compact: true
                            iconName: "clock"
                            text: qsTr("Show evidence")
                            onClicked: view.inspector.showOrdinal(fact.ordinal)
                        }
                        AppButton {
                            visible: fact.section !== ""
                            kind: "quiet"
                            compact: true
                            iconName: "external-link"
                            text: fact.cite
                            toolTipText: qsTr("Open this section of the specification in your browser")
                            onClicked: view.inspector.openSpec(fact.section)
                        }
                    }
                }
            }
        }
    }
}
