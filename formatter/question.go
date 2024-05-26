package formatter

import "fmt"

type questionFormatter struct{}

var _ Formatter = (*questionFormatter)(nil)

func (questionFormatter) Format(msg MessageWrap) string {
	question := msg.Msg.QuestionSec
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s", msg.Device, msg.Server, question.Name, question.Type, msg.Duration)
}
