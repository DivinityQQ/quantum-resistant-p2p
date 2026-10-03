import QtQuick
import Qrp2p.Theme

// A Lucide icon in a theme colour (rendered by qrp2p.ui.icons at the screen's pixel density).
// Decorative by default: set Accessible.ignored to false and a name where it carries meaning.
Item {
    id: icon

    property string name
    property color color: Theme.text
    property int size: Theme.iconSize

    implicitWidth: size
    implicitHeight: size
    Accessible.ignored: true

    Image {
        anchors.fill: parent
        sourceSize.width: Math.ceil(icon.size * Screen.devicePixelRatio)
        sourceSize.height: Math.ceil(icon.size * Screen.devicePixelRatio)
        source: icon.name ? "image://icon/" + icon.name + "?color=" + String(icon.color).slice(1) : ""
        fillMode: Image.PreserveAspectFit
        smooth: true
    }
}
