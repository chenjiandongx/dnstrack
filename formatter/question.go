package formatter

import (
	"fmt"
	"time"
)

type questionFormatter struct {
	f *Filter
}

var _ Formatter = (*questionFormatter)(nil)

func (qf questionFormatter) Format(msg MessageWrap) (string, bool) {
	if qf.f != nil && !qf.f.Pass(msg) {
		return "", false
	}

	q := msg.Msg.QuestionSec
	s := fmt.Sprintf("%s\t<%s>@%s\t%s\t%s\t%s", msg.When.Format(time.RFC3339), msg.Device, msg.Server, q.Type, msg.Duration, q.Name)
	return s, true
}
