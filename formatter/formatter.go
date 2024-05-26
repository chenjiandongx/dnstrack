package formatter

import (
	"time"

	"github.com/chenjiandongx/dnstrack/codec"
)

type MessageWrap struct {
	Duration time.Duration  `json:"duration" yaml:"duration"`
	Device   string         `json:"device" yaml:"device"`
	Server   string         `json:"server" yaml:"server"`
	Msg      *codec.Message `json:"message" yaml:"message"`
}

type Formatter interface {
	Format(msg MessageWrap) string
}

func New(t string) Formatter {
	switch t {
	case "question", "q":
		return questionFormatter{}
	case "json", "j":
		return jsonFormatter{}
	case "yaml", "y":
		return yamlFormatter{}
	default:
		return verboseFormatter{}
	}
}
