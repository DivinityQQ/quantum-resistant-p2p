import QtQuick
import Qrp2p.Theme

// Busy activity without a fabricated percentage. Under reduced motion it stands still.
Icon {
    id: spinner

    property bool running: true

    name: "loader-circle"
    color: Theme.textSecondary
    Accessible.ignored: false
    Accessible.role: Accessible.Animation
    Accessible.name: qsTr("Working")

    RotationAnimator on rotation {
        from: 0
        to: 360
        duration: 900
        loops: Animation.Infinite
        running: spinner.running && spinner.visible && !Theme.reducedMotion
    }
}
