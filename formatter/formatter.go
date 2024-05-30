package formatter

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
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

func New(format, server, typ string, n int) Formatter {
	f := NewFilter(server, typ)
	switch format {
	case "question", "q":
		return questionFormatter{f, n}
	case "json", "j":
		return jsonFormatter{f}
	case "yaml", "y":
		return yamlFormatter{f}
	default:
		return verboseFormatter{f}
	}
}

func formatDuration(d time.Duration) string {
	s := d.String()
	units := []string{"ms", "µs", "ns", "h", "m", "s"}
	for _, unit := range units {
		if strings.HasSuffix(s, unit) {
			v := s[:len(s)-len(unit)]
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return s
			}
			fs := fmt.Sprintf("%.3f", f)
			switch len(fs) {
			case 6:
				fs = pad(1) + fs
			case 5:
				fs = pad(2) + fs
			case 4:
				fs = pad(3) + fs
			}
			return pad(2-len(unit)) + fs + unit
		}
	}
	return s
}

func formatIface(s string, maxIfaceLen int) string {
	n := maxIfaceLen - len(s)
	return pad(n) + s
}

func formatServer(s string) string {
	const maxServerLen = 18 // 172.172.172.172:53
	n := maxServerLen - len(s)
	return pad(n) + s
}

func formatType(s string) string {
	const maxTypeLen = 5 // CNAME
	n := maxTypeLen - len(s)
	return pad(n) + s
}

func pad(n int) string {
	buf := &bytes.Buffer{}
	for i := 0; i < n; i++ {
		buf.WriteString(" ")
	}
	return buf.String()
}
