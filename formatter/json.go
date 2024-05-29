package formatter

import (
	"encoding/json"
)

type jsonFormatter struct {
	f *Filter
}

var _ Formatter = (*jsonFormatter)(nil)

func (jf jsonFormatter) Format(msg MessageWrap) (string, bool) {
	if jf.f != nil && !jf.f.Pass(msg) {
		return "", false
	}

	b, _ := json.Marshal(msg)
	return string(b), true
}
