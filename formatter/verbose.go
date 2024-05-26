package formatter

import (
	"bytes"
	"fmt"
)

type verboseFormatter struct{}

var _ Formatter = (*verboseFormatter)(nil)

func (verboseFormatter) Format(msg MessageWrap) string {
	buf := &bytes.Buffer{}
	buf.WriteString("--------------------\n\n")
	buf.WriteString(fmt.Sprintf("; Devide: %s, Server: %s, Elapsed: %v\n", msg.Device, msg.Server, msg.Duration))

	question := msg.Msg.QuestionSec
	buf.WriteString("\n;; Question Section:\n")
	buf.WriteString(fmt.Sprintf("%s\t %s\n", question.Name, question.Type))

	answer := msg.Msg.AnswerSec
	if len(answer) <= 0 {
		buf.WriteString("\n;; Answer Section: <empty>")
	} else {
		buf.WriteString("\n;; Answer Section:\n")
		for _, item := range answer {
			buf.WriteString(fmt.Sprintf("%s\t %s\t %d\t %s\n", item.Name, item.Type, item.TTL, item.Record))
		}
	}

	authority := msg.Msg.AuthoritySec
	if len(authority) <= 0 {
		buf.WriteString("\n;; Authority Section: <empty>")
	} else {
		buf.WriteString("\n;; Authority Section:\n")
		for _, item := range authority {
			buf.WriteString(fmt.Sprintf("%s\t %s\t %s\n", item.Name, item.Type, item.Record))
		}
	}

	additional := msg.Msg.AdditionalSec
	if len(additional) <= 0 {
		buf.WriteString("\n;; Additional Section: <empty>\n")
	} else {
		buf.WriteString("\n;; Additional Section:\n")
		for _, item := range additional {
			buf.WriteString(fmt.Sprintf("%s\t %s\t %s\n", item.Name, item.Type, item.Record))
		}
	}

	return buf.String()
}
