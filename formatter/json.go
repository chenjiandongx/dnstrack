package formatter

import (
	"encoding/json"
)

type jsonFormatter struct{}

var _ Formatter = (*jsonFormatter)(nil)

func (jsonFormatter) Format(msg MessageWrap) string {
	b, _ := json.Marshal(msg)
	return string(b)
}
