import QtQuick
import QtQuick.Layouts
import QtQuick.Dialogs
import Qrp2p.Theme
import Qrp2p.Components

// One conversation: header, the session's exposure and connection state, messages, composer.
// A glass-box session keeps its amber frame and banner in every layout (UI_DESIGN §8).
Item {
    id: view

    required property var conversation

    signal verify()
    signal details()
    signal confirm(string action)

    readonly property int column: Math.max(280, Math.min(Theme.readingWidth, width - Theme.s6 * 2))

    function focusComposer() {
        composer.focusInput()
    }

    // Exposure frame: present whenever the session is glass-box.
    Rectangle {
        anchors.fill: parent
        anchors.margins: Theme.s1
        z: 5
        visible: view.conversation.glassBox
        color: "transparent"
        radius: Theme.radiusCard
        border.width: 2
        border.color: Theme.exposureText
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        ConversationHeader {
            Layout.preferredWidth: view.column
            Layout.alignment: Qt.AlignHCenter
            conversation: view.conversation
            onVerify: view.verify()
            onDetails: view.details()
            onConfirm: action => view.confirm(action)
        }
        Banner {
            Layout.preferredWidth: view.column
            Layout.alignment: Qt.AlignHCenter
            Layout.bottomMargin: Theme.s2
            visible: view.conversation.glassBox
            kind: "exposure"
            iconName: "eye"
            text: qsTr("Glass-box session: all keys and messages of this session are visible to both of you and can be saved. Identity private keys never are.")
        }
        Banner {
            Layout.preferredWidth: view.column
            Layout.alignment: Qt.AlignHCenter
            Layout.bottomMargin: Theme.s2
            visible: view.conversation.banner !== ""
            text: view.conversation.bannerText
            busy: view.conversation.banner === "connecting" || view.conversation.banner === "waiting"
            kind: view.conversation.bannerTone
            dismissible: !busy
            onDismissed: view.conversation.dismissBanner()

            AppButton {
                visible: (view.conversation.banner === "error" || view.conversation.banner === "ended")
                    && view.conversation.trust !== "blocked"
                compact: true
                text: view.conversation.banner === "ended" ? qsTr("Reconnect") : qsTr("Try again")
                onClicked: view.conversation.connectSession()
            }
            AppButton {
                objectName: "useOfferedProfile"
                visible: view.conversation.banner === "profile"
                compact: true
                text: qsTr("Use %1").arg(view.conversation.offeredProfile)
                onClicked: view.conversation.useOfferedProfile()
            }
        }
        MessageList {
            id: messages
            Layout.fillWidth: true
            Layout.fillHeight: true
            conversation: view.conversation
            columnWidth: view.column
            onSaveTo: id => {
                folderDialog.fileId = id
                folderDialog.open()
            }
            onVerify: view.verify()
        }
        Composer {
            id: composer
            Layout.preferredWidth: view.column
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Theme.s2
            Layout.bottomMargin: Theme.s4
            conversation: view.conversation
            onAttach: fileDialog.open()
        }
    }

    // Drop a file anywhere on the conversation to offer it.
    DropArea {
        id: drop
        anchors.fill: parent
        enabled: view.conversation.online
        keys: ["text/uri-list"]
        onDropped: drop => {
            for (const url of drop.urls)
                view.conversation.sendFile(url.toString())
            drop.acceptProposedAction()
        }

        Rectangle {
            anchors.fill: parent
            anchors.margins: Theme.s4
            visible: drop.containsDrag
            radius: Theme.radiusCard
            color: Theme.selectionFill
            opacity: 0.95
            border.width: 2
            border.color: Theme.focus

            AppText {
                anchors.centerIn: parent
                text: qsTr("Drop to offer to %1").arg(Theme.isolate(view.conversation.name))
                role: "title"
                color: Theme.selectionText
            }
        }
    }

    FileDialog {
        id: fileDialog
        title: qsTr("Send a file to %1").arg(view.conversation.name)
        fileMode: FileDialog.OpenFiles
        onAccepted: {
            for (const url of selectedFiles)
                view.conversation.sendFile(url.toString())
        }
    }

    FolderDialog {
        id: folderDialog
        property string fileId: ""
        title: qsTr("Save the file in")
        onAccepted: view.conversation.acceptFileTo(fileId, selectedFolder.toString())
    }
}
