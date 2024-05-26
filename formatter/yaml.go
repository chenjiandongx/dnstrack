package formatter

import "gopkg.in/yaml.v3"

type yamlFormatter struct{}

var _ Formatter = (*yamlFormatter)(nil)

func (yamlFormatter) Format(msg MessageWrap) string {
	b, _ := yaml.Marshal(msg)
	return string(b)
}
