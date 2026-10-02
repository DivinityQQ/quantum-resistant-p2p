pragma Singleton
import QtQuick

// Semantic tokens for colour, type, geometry and motion (UI_DESIGN §4). Components use these
// names; they never pick their own hex values. Main.qml binds the user's preferences in.
QtObject {
    id: theme

    // -- preferences (bound by Main.qml) -------------------------------------------------------
    property string preference: "system"   // system | light | dark
    property bool reducedMotion: false
    property int textScale: 100            // percent
    property string monoFamily: ""          // an installed family, set by Main.qml from Python

    readonly property bool dark: preference === "dark"
        || (preference === "system" && Qt.styleHints.colorScheme === Qt.ColorScheme.Dark)

    // -- colour (UI_DESIGN §4.1) -----------------------------------------------------------------
    readonly property color canvas: dark ? "#151718" : "#FAF9F6"
    readonly property color surface: dark ? "#1D2022" : "#FFFFFF"
    readonly property color surfaceSubtle: dark ? "#24282A" : "#F0EFEB"
    readonly property color text: dark ? "#EFF1F2" : "#242628"
    readonly property color textSecondary: dark ? "#B3B7BA" : "#60666B"
    readonly property color divider: dark ? "#3A3F43" : "#DEDFDB"
    readonly property color controlBoundary: dark ? "#9AA1A6" : "#858B90"
    readonly property color primaryFill: dark ? "#EFF1F2" : "#242628"
    readonly property color primaryText: dark ? "#151718" : "#FFFFFF"
    readonly property color selectionFill: dark ? "#253446" : "#E7EDF6"
    readonly property color selectionText: dark ? "#BBD1F1" : "#294D79"
    readonly property color focus: dark ? "#91B4E8" : "#365D96"
    readonly property color success: dark ? "#91CDA3" : "#2D653F"
    readonly property color exposureText: dark ? "#EAC17C" : "#865517"
    readonly property color exposureFill: dark ? "#382D1E" : "#FFF2DA"
    readonly property color labText: dark ? "#BEADF3" : "#614687"
    readonly property color labFill: dark ? "#2E273B" : "#F2ECFA"
    readonly property color dangerText: dark ? "#EE9B9B" : "#AA343D"
    readonly property color dangerFill: dark ? "#392329" : "#FBEAEC"
    // Interaction states between canvas and surfaceSubtle; distinct from selection and focus.
    readonly property color hoverFill: dark ? "#202426" : "#F4F3EF"
    readonly property color pressedFill: dark ? "#2B3033" : "#E7E6E1"
    readonly property color primaryHover: dark ? "#FFFFFF" : "#3A3D40"
    readonly property color scrim: dark ? "#99000000" : "#59242628"
    readonly property color online: dark ? "#7FC495" : "#2F8A4C"
    readonly property color avatarFill: dark ? "#2C3134" : "#E6E5E0"

    // -- type (UI_DESIGN §4.3) -------------------------------------------------------------------
    readonly property string family: "Inter"
    readonly property real scale: textScale / 100
    readonly property int sizeBody: Math.round(15 * scale)
    readonly property int sizeSmall: Math.round(13 * scale)
    readonly property int sizeLabel: Math.round(12 * scale)
    readonly property int sizeTitle: Math.round(19 * scale)
    readonly property int sizeHeading: Math.round(26 * scale)
    readonly property int sizeMono: Math.round(13 * scale)
    readonly property int weightRegular: Font.Normal
    readonly property int weightMedium: Font.Medium

    // -- geometry ------------------------------------------------------------------------------------
    readonly property int s1: 4
    readonly property int s2: 8
    readonly property int s3: 12
    readonly property int s4: 16
    readonly property int s6: 24
    readonly property int s8: 32
    readonly property int controlHeight: Math.round(36 * Math.max(1, (scale + 1) / 2))
    readonly property int radiusControl: 8
    readonly property int radiusCard: 12
    readonly property int radiusBubble: 16
    readonly property int radiusTight: 4
    readonly property int readingWidth: Math.round(760 * Math.max(1, scale * 0.9))
    readonly property int iconSize: Math.round(18 * Math.max(1, (scale + 1) / 2))

    // -- motion ----------------------------------------------------------------------------------------
    readonly property int motion: reducedMotion ? 0 : 200
    readonly property int motionFast: reducedMotion ? 0 : 120

    // A name embedded in a sentence: an isolate keeps right-to-left text from reordering it.
    function isolate(text) {
        return "\u2068" + text + "\u2069"
    }
}
