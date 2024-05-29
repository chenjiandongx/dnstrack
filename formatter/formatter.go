package formatter

import (
	"time"

	"github.com/chenjiandongx/dnstrack/codec"
)

type MessageWrap struct {
	When     time.Time      `json:"time" yaml:"time"`
	Size     int            `json:"size" yaml:"size"`
	Duration time.Duration  `json:"duration" yaml:"duration"`
	Device   string         `json:"device" yaml:"device"`
	Server   string         `json:"server" yaml:"server"`
	Msg      *codec.Message `json:"message" yaml:"message"`
}

type Formatter interface {
	Format(msg MessageWrap) (string, bool)
}

func New(format, server, typ string) Formatter {
	f := NewFilter(server, typ)
	switch format {
	case "question", "q":
		return questionFormatter{f}
	case "json", "j":
		return jsonFormatter{f}
	case "yaml", "y":
		return yamlFormatter{f}
	default:
		return verboseFormatter{f}
	}
}
