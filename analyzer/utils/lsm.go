package utils

type LSMAction int

const (
	LSMActionPause LSMAction = iota
	LSMActionNext
	LSMActionReset
	LSMActionCancel
)

type LinearStateMachine struct {
	Steps []func() LSMAction

	index     int
	cancelled bool
}

func NewLinearStateMachine(steps ...func() LSMAction) *LinearStateMachine {
	return &LinearStateMachine{
		Steps: steps,
	}
}

// Run runs the state machine until it pauses, finishes or is cancelled.
func (lsm *LinearStateMachine) Run() (cancelled bool, done bool) {
	if lsm.index >= len(lsm.Steps) {
		return lsm.cancelled, true
	}
	for lsm.index < len(lsm.Steps) {
		action := lsm.Steps[lsm.index]()
		switch action {
		case LSMActionPause:
			return false, false
		case LSMActionNext:
			lsm.index++
		case LSMActionReset:
			lsm.index = 0
		case LSMActionCancel:
			lsm.cancelled = true
			return true, true
		}
	}
	return false, true
}

func (lsm *LinearStateMachine) AppendSteps(steps ...func() LSMAction) {
	lsm.Steps = append(lsm.Steps, steps...)
}

func (lsm *LinearStateMachine) Reset() {
	lsm.index = 0
	lsm.cancelled = false
}
