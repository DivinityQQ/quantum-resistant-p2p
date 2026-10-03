import QtQuick
import Qrp2p.Theme

// Text for the whole interface. Always plain text: peer data must never be parsed as rich text
// or HTML (DESIGN §14.3), so this component fixes the format and the other components use it
// instead of a bare Text (tests/ui/test_qml_rules.py enforces both).
Text {
    // body | secondary | small | label | title | heading | mono
    property string role: "body"

    textFormat: Text.PlainText
    color: role === "secondary" || role === "small" || role === "label"
        ? Theme.textSecondary : Theme.text
    linkColor: color
    font.family: role === "mono" ? Theme.monoFamily : Theme.family
    font.pixelSize: role === "heading" ? Theme.sizeHeading
        : role === "title" ? Theme.sizeTitle
        : role === "small" || role === "label" ? Theme.sizeSmall
        : role === "mono" ? Theme.sizeMono
        : Theme.sizeBody
    font.weight: role === "heading" || role === "title" || role === "label"
        ? Theme.weightMedium : Theme.weightRegular
    font.features: { "tnum": 1 }
}
