import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components

// A contact in the strip: name, availability, unread count; trust and ID in its description.
T.Button {
    id: chip

    required property string contactId
    required property string name
    required property string initial
    required property string trust
    required property string presence
    required property string presenceText
    required property int unread
    required property bool glassBox
    required property string description
    property bool selected: false

    implicitHeight: 56
    implicitWidth: Math.min(220, row.implicitWidth + Theme.s3 * 2)
    leftPadding: Theme.s3
    rightPadding: Theme.s3
    hoverEnabled: true
    focusPolicy: Qt.StrongFocus
    Accessible.role: Accessible.Button
    Accessible.name: description
    Accessible.checkable: true
    Accessible.checked: selected

    contentItem: RowLayout {
        id: row
        spacing: Theme.s3

        Avatar {
            initial: chip.initial
            unread: chip.unread
            size: 36
        }
        ColumnLayout {
            spacing: 1
            Layout.maximumWidth: 140

            RowLayout {
                spacing: Theme.s1
                AppText {
                    text: chip.name
                    font.weight: Theme.weightMedium
                    elide: Text.ElideRight
                    Layout.maximumWidth: 120
                }
                Icon {
                    visible: chip.trust === "verified"
                    name: "shield-check"
                    color: Theme.success
                    size: Theme.iconSize - 4
                }
                Icon {
                    visible: chip.glassBox
                    name: "eye"
                    color: Theme.exposureText
                    size: Theme.iconSize - 4
                }
            }
            RowLayout {
                spacing: Theme.s1 + 2
                PresenceDot {
                    presence: chip.presence
                }
                AppText {
                    text: chip.presenceText
                    role: "small"
                    elide: Text.ElideRight
                    Layout.maximumWidth: 120
                }
            }
        }
    }

    background: Rectangle {
        radius: Theme.radiusCard
        color: chip.selected ? Theme.surfaceSubtle
            : chip.down ? Theme.pressedFill
            : chip.hovered ? Theme.hoverFill : "transparent"

        FocusRing {
            visible: chip.visualFocus
            cornerRadius: Theme.radiusCard
        }
    }

    AppToolTip {
        visible: chip.hovered
        text: chip.description
    }
}
