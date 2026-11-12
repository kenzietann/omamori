package tui

import (
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const shadowStrength = 0.6

type rgb struct {
	red, green, blue int
}

var gradientStops = []rgb{{56, 189, 248}, {58, 127, 246}, {155, 107, 255}}

func (color rgb) hex() string {
	return fmt.Sprintf("#%02x%02x%02x", color.red, color.green, color.blue)
}

func lerp(from, to int, fraction float64) int {
	return int(math.Round(float64(from) + float64(to-from)*fraction))
}

func gradientColor(position float64) rgb {
	position = math.Min(math.Max(position, 0), 1)

	segments := len(gradientStops) - 1
	scaled := position * float64(segments)
	index := min(int(scaled), segments-1)
	fraction := scaled - float64(index)
	from, to := gradientStops[index], gradientStops[index+1]

	return rgb{lerp(from.red, to.red, fraction), lerp(from.green, to.green, fraction), lerp(from.blue, to.blue, fraction)}
}

func darken(color rgb, strength float64) rgb {
	scale := func(channel int) int {
		return min(max(int(math.Round(float64(channel)*strength)), 0), 255)
	}

	return rgb{scale(color.red), scale(color.green), scale(color.blue)}
}

// gradientRow colors each character by its column. The text itself never changes.
func gradientRow(row string, width int) string {
	var line strings.Builder

	column := 0
	for _, character := range row {
		if character != ' ' {
			color := gradientColor(float64(column) / float64(max(width-1, 1)))
			if character != '█' {
				color = darken(color, shadowStrength)
			}
			line.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(color.hex())).Render(string(character)))
		} else {
			line.WriteRune(character)
		}
		column++
	}

	return line.String()
}
