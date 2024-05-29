package formatter

import (
	"bytes"
	"fmt"
	"time"
)

type verboseFormatter struct {
	f *Filter
}

var _ Formatter = (*verboseFormatter)(nil)

func (vf verboseFormatter) Format(msg MessageWrap) (string, bool) {
	if vf.f != nil && !vf.f.Pass(msg) {
		return "", false
	}

	buf := &bytes.Buffer{}
	buf.WriteString("--------------------\n\n")

	header := msg.Msg.Header
	buf.WriteString(fmt.Sprintf("; <%s>@%s, ID: %d, OpCpde: %s, Status: %s\n", msg.Device, msg.Server, header.ID, header.OpCode, header.Status))
	buf.WriteString(fmt.Sprintf(";; When: %s\n", msg.When.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf(";; Query Time: %s\n", msg.Duration))
	buf.WriteString(fmt.Sprintf(";; Msg Size: %dB\n", msg.Size))

	question := msg.Msg.QuestionSec
	buf.WriteString("\n;; Question Section:\n")
	buf.WriteString(fmt.Sprintf("%s\t %s\n", question.Name, question.Type))

	answer := msg.Msg.AnswerSec
	if len(answer) <= 0 {
		buf.WriteString("\n;; Answer Section: <empty>")
	} else {
		buf.WriteString("\n;; Answer Section:\n")
		for _, item := range answer {
			buf.WriteString(fmt.Sprintf("%s\t %d\t %s\t %s\t %s\n", item.Name, item.TTL, item.Type, item.Class, item.Record))
		}
	}

	authority := msg.Msg.AuthoritySec
	if len(authority) <= 0 {
		buf.WriteString("\n;; Authority Section: <empty>")
	} else {
		buf.WriteString("\n;; Authority Section:\n")
		for _, item := range authority {
			buf.WriteString(fmt.Sprintf("%s\t %s\t %s\t %s\n", item.Name, item.Type, item.Class, item.Record))
		}
	}

	additional := msg.Msg.AdditionalSec
	if len(additional) <= 0 {
		buf.WriteString("\n;; Additional Section: <empty>\n")
	} else {
		buf.WriteString("\n;; Additional Section:\n")
		for _, item := range additional {
			buf.WriteString(fmt.Sprintf("%s\t %s\t %s\t %s\n", item.Name, item.Type, item.Class, item.Record))
		}
	}

	return buf.String(), true
}
