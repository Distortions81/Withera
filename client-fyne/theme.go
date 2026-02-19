package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Palette lifted from client-web/webui.html CSS variables.
var (
	witheraBG     = color.NRGBA{R: 0x0d, G: 0x12, B: 0x17, A: 0xff}
	witheraPanel  = color.NRGBA{R: 0x15, G: 0x1d, B: 0x25, A: 0xff}
	witheraText   = color.NRGBA{R: 0xe6, G: 0xed, B: 0xf3, A: 0xff}
	witheraMuted  = color.NRGBA{R: 0x8e, G: 0x9a, B: 0xa7, A: 0xff}
	witheraAccent = color.NRGBA{R: 0x55, G: 0xb2, B: 0xff, A: 0xff}
	witheraLine   = color.NRGBA{R: 0x26, G: 0x33, B: 0x41, A: 0xff}

	witheraInputBG = color.NRGBA{R: 0x10, G: 0x17, B: 0x1f, A: 0xff}
)

type witheraTheme struct{}

func (witheraTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return witheraBG
	case theme.ColorNameForeground:
		return witheraText
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x6f, G: 0x7b, B: 0x87, A: 0xff}
	case theme.ColorNameInputBackground:
		return witheraInputBG
	case theme.ColorNamePlaceHolder:
		return witheraMuted
	case theme.ColorNamePrimary:
		return witheraAccent
	case theme.ColorNameFocus, theme.ColorNameSelection:
		return color.NRGBA{R: 0x78, G: 0xc8, B: 0xff, A: 0x88}
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x78, G: 0xc8, B: 0xff, A: 0x22}
	case theme.ColorNameButton:
		// Let buttons inherit accent via Primary where used; default to panel-ish.
		return witheraPanel
	case theme.ColorNameSeparator, theme.ColorNameShadow:
		return witheraLine
	}
	return theme.DefaultTheme().Color(name, variant)
}

func (witheraTheme) Font(style fyne.TextStyle) fyne.Resource {
	// Prefer monospace to match the web UI.
	style.Monospace = true
	return theme.DefaultTheme().Font(style)
}

func (witheraTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (witheraTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInlineIcon:
		return 18
	}
	return theme.DefaultTheme().Size(name)
}
