import QtQuick
import Qrp2p.Theme

// A group heading inside a pane or dialog.
AppText {
    role: "label"
    color: Theme.textSecondary
    topPadding: Theme.s2
    Accessible.role: Accessible.Heading
}
