package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	homeScreen screen = iota
	runScreen
	resultsScreen
)

const (
	menuTaskA = iota
	menuTaskB
	menuQuit
)

const stepBuffer = 256

type Result struct {
	Report   string
	Complete bool
}

type Runner func(ctx context.Context, step func(text string)) (Result, error)

type stepMsg struct {
	run  int
	text string
}

type stepsEndedMsg struct{}

type doneMsg struct {
	run    int
	result Result
	err    error
}

type Model struct {
	screen      screen
	target      string
	runner      Runner
	cursor      int
	notice      string
	steps       []string
	report      string
	stopped     bool
	running     bool
	cancelling  bool
	cancel      context.CancelFunc
	runID       int
	stepChannel chan string
	scroll      int
	width       int
	height      int
}

func New(target string, runner Runner) Model {
	return Model{target: target, runner: runner}
}

func (model Model) Init() tea.Cmd {
	return nil
}

func (model Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = message.Width, message.Height
		model.scroll = min(model.scroll, model.maxScroll())

		return model, nil
	case tea.KeyMsg:
		return model.handleKey(message.String())
	case stepMsg:
		if message.run != model.runID {
			return model, nil
		}
		model.steps = append(model.steps, message.text)

		return model, waitForStep(model.runID, model.stepChannel)
	case doneMsg:
		if message.run != model.runID || !model.running {
			return model, nil
		}
		model.running = false
		model.cancelling = false
		model.cancel()
		model.stopped = message.err != nil || !message.result.Complete
		model.report = message.result.Report
		if message.err != nil {
			model.report = "The run stopped: " + message.err.Error()
		}
		model.screen = resultsScreen
		model.scroll = 0

		return model, nil
	}

	return model, nil
}

func (model Model) handleKey(key string) (tea.Model, tea.Cmd) {
	if key == "q" || key == "ctrl+c" {
		model.stopRun()

		return model, tea.Quit
	}

	switch model.screen {
	case homeScreen:
		return model.handleHomeKey(key)
	case runScreen:
		if key == "esc" && !model.cancelling {
			model.cancelling = true
			model.cancel()
		}
	case resultsScreen:
		return model.handleResultsKey(key), nil
	}

	return model, nil
}

func (model Model) handleHomeKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up":
		model.cursor = max(model.cursor-1, 0)
		model.notice = ""
	case "down":
		model.cursor = min(model.cursor+1, menuQuit)
		model.notice = ""
	case "enter":
		switch model.cursor {
		case menuTaskA:
			if model.target == "" || model.runner == nil {
				model.notice = "There is no target folder. Start Omamori with a folder: omamori <folder>"
				return model, nil
			}

			return model.startRun()
		case menuTaskB:
			model.notice = "Task B is not built yet."
		case menuQuit:
			return model, tea.Quit
		}
	}

	return model, nil
}

func (model Model) handleResultsKey(key string) Model {
	pageSize := max(model.viewHeight(), 1)

	switch key {
	case "b", "esc":
		model.screen = homeScreen
		model.notice = ""
	case "up":
		model.scroll = max(model.scroll-1, 0)
	case "down":
		model.scroll = min(model.scroll+1, model.maxScroll())
	case "pgup":
		model.scroll = max(model.scroll-pageSize, 0)
	case "pgdown":
		model.scroll = min(model.scroll+pageSize, model.maxScroll())
	}

	return model
}

func (model *Model) stopRun() {
	if model.running && model.cancel != nil {
		model.cancel()
	}
}

func (model Model) startRun() (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	steps := make(chan string, stepBuffer)

	model.runID++
	model.screen = runScreen
	model.running = true
	model.cancelling = false
	model.cancel = cancel
	model.stepChannel = steps
	model.steps = nil
	model.report = ""
	model.stopped = false
	model.notice = ""

	runID, runner := model.runID, model.runner
	runCommand := func() tea.Msg {
		result, err := runner(ctx, func(text string) {
			select {
			case steps <- text:
			default:
			}
		})
		close(steps)

		return doneMsg{run: runID, result: result, err: err}
	}

	return model, tea.Batch(runCommand, waitForStep(runID, steps))
}

func waitForStep(runID int, steps <-chan string) tea.Cmd {
	return func() tea.Msg {
		text, open := <-steps
		if !open {
			return stepsEndedMsg{}
		}

		return stepMsg{run: runID, text: text}
	}
}
