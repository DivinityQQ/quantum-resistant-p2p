import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import Qrp2p.Theme
import Qrp2p.Components
import Qrp2p.Inspector

// The solo lab (UI_DESIGN §8, §3.4): the controls of a run beside the lab's own Inspector. The
// LAB label stays in every layout. Step and Run follow the lab controller: at the end of a run
// (or a diverged replay) only Reset and Fork remain. Narrow windows show the controls or the
// Inspector, one at a time.
Item {
    id: screen

    required property var lab

    signal backToChat()

    objectName: "labScreen"
    readonly property bool wide: width >= 1000 * Math.max(1, Theme.scale)
    property string pane: "controls"   // narrow windows: controls | inspector
    readonly property bool terminal: lab.phase === "ended" || lab.phase === "diverged"

    function focusFirst() {
        stepButton.forceActiveFocus(Qt.TabFocusReason)
    }

    Rectangle {
        anchors.fill: parent
        color: Theme.canvas
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // -- what this is, which profile, and a fresh start ----------------------------------------
        RowLayout {
            Layout.fillWidth: true
            Layout.margins: Theme.s3
            Layout.leftMargin: Theme.s4
            spacing: Theme.s2

            AppButton {
                kind: "quiet"
                compact: true
                iconName: "arrow-left"
                text: screen.wide ? qsTr("Back to chat") : ""
                toolTipText: qsTr("Back to chat")
                onClicked: screen.backToChat()
            }
            AppText {
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                Layout.preferredWidth: Math.ceil(implicitWidth)
                Layout.maximumWidth: Math.ceil(implicitWidth)
                text: qsTr("Solo lab")
                role: "title"
                elide: Text.ElideRight
                Accessible.role: Accessible.Heading
            }
            Tag {
                objectName: "labTag"
                text: qsTr("LAB")
                kind: "lab"
                iconName: "flask-conical"
            }
            Item {
                Layout.fillWidth: true
            }
            AppComboBox {
                id: profileChoice
                objectName: "labProfile"
                implicitWidth: 170
                label: qsTr("Profile for the next run")
                current: screen.lab.profile
                options: screen.lab.profiles.map(p => ({ value: p, label: p }))
                onChosen: value => screen.lab.reset(value)
            }
            AppButton {
                objectName: "labReset"
                compact: true
                kind: "secondary"
                iconName: "rotate-ccw"
                text: screen.wide ? qsTr("Reset") : ""
                toolTipText: qsTr("A fresh run: new identities, nothing sent yet")
                enabled: !screen.lab.busy
                onClicked: screen.lab.reset(screen.lab.profile)
            }
        }
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 2
            color: Theme.labText
            opacity: 0.6
        }

        SegmentedControl {
            Layout.margins: Theme.s2
            Layout.alignment: Qt.AlignHCenter
            visible: !screen.wide
            label: qsTr("Show")
            current: screen.pane
            options: [
                { value: "controls", label: qsTr("Lab") },
                { value: "inspector", label: qsTr("Inspector") }
            ]
            onChosen: value => screen.pane = value
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // -- the controls -----------------------------------------------------------------------
            Flickable {
                id: controls
                Layout.fillHeight: true
                Layout.fillWidth: !screen.wide
                Layout.preferredWidth: screen.wide ? Math.round(Math.max(340, screen.width * 0.3)) : -1
                visible: screen.wide || screen.pane === "controls"
                contentHeight: panel.implicitHeight + Theme.s4 * 2
                boundsBehavior: Flickable.StopAtBounds
                clip: true
                T.ScrollBar.vertical: AppScrollBar {}

                ColumnLayout {
                    id: panel
                    x: Theme.s4
                    y: Theme.s4
                    width: controls.width - Theme.s4 * 2 - Theme.scrollGutter
                    spacing: Theme.s3

                    Banner {
                        Layout.fillWidth: true
                        visible: screen.lab.phase === "diverged"
                        kind: "danger"
                        text: screen.lab.note
                    }

                    // Step: what it will do, said on the button itself.
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.s2

                        AppButton {
                            id: stepButton
                            objectName: "labStep"
                            Layout.fillWidth: true
                            kind: "primary"
                            iconName: "step-forward"
                            busy: screen.lab.busy
                            enabled: screen.lab.nextStep !== "" && !screen.terminal
                            text: screen.lab.nextStep !== "" ? qsTr("Step: %1").arg(screen.lab.nextStep)
                                : screen.terminal ? qsTr("The run has ended") : qsTr("Nothing in flight")
                            onClicked: screen.lab.step()
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.s2

                            AppButton {
                                objectName: "labRun"
                                Layout.fillWidth: true
                                compact: true
                                iconName: "play"
                                text: qsTr("Run")
                                toolTipText: qsTr("Take the default steps (deliver the oldest frame, Bob admits) until nothing is in flight")
                                enabled: screen.lab.nextStep !== "" && !screen.terminal && !screen.lab.busy
                                onClicked: screen.lab.run()
                            }
                            AppButton {
                                objectName: "labWait"
                                Layout.fillWidth: true
                                compact: true
                                iconName: "clock"
                                text: qsTr("Wait 30 s")
                                toolTipText: qsTr("Let time pass on the lab clock: pings, timeouts")
                                enabled: screen.lab.phase !== "ready" && !screen.terminal && !screen.lab.busy
                                onClicked: screen.lab.wait()
                            }
                        }
                        AppText {
                            Layout.fillWidth: true
                            objectName: "labNote"
                            visible: screen.lab.note !== "" && screen.lab.phase !== "diverged"
                            text: screen.lab.note
                            wrapMode: Text.Wrap
                        }
                        AppText {
                            Layout.fillWidth: true
                            text: qsTr("Lab clock %1 s · %2").arg(screen.lab.labTime.toFixed(2)).arg(screen.lab.profile)
                            role: "small"
                        }
                    }

                    // Frames sent and not yet delivered.
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.s1

                        AppText {
                            text: qsTr("In flight")
                            role: "label"
                        }
                        AppText {
                            Layout.fillWidth: true
                            visible: screen.lab.inFlight.length === 0
                            text: qsTr("Nothing: choose what Alice or Bob does next.")
                            role: "small"
                            wrapMode: Text.Wrap
                        }
                        Repeater {
                            model: screen.lab.inFlight

                            AppText {
                                required property string modelData
                                required property int index
                                Layout.fillWidth: true
                                text: (index === 0 ? "→ " : "   ") + modelData
                                role: "small"
                                elide: Text.ElideRight
                                color: index === 0 ? Theme.text : Theme.textSecondary
                            }
                        }
                    }

                    LabNode {
                        Layout.fillWidth: true
                        lab: screen.lab
                        side: "alice"
                    }
                    LabNode {
                        Layout.fillWidth: true
                        lab: screen.lab
                        side: "bob"
                    }
                    LabSteps {
                        Layout.fillWidth: true
                        lab: screen.lab
                    }
                }
            }

            // -- the lab's Inspector: Alice's or Bob's view of the run -----------------------------
            InspectorPane {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: screen.wide || screen.pane === "inspector"
                inspector: screen.lab.inspector
                split: true
                canExpand: false
            }
        }
    }
}
