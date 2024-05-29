package formatter

import "gopkg.in/yaml.v3"

type yamlFormatter struct {
	f *Filter
}

var _ Formatter = (*yamlFormatter)(nil)

func (yf yamlFormatter) Format(msg MessageWrap) (string, bool) {
	if yf.f != nil && !yf.f.Pass(msg) {
		return "", false
	}

	b, _ := yaml.Marshal(msg)
	return string(b), true
}
