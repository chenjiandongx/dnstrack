package formatter

type Filter struct {
	server string
	typ    string
}

func NewFilter(server, typ string) *Filter {
	return &Filter{
		server: server,
		typ:    typ,
	}
}

func (f Filter) Pass(msg MessageWrap) bool {
	if f.server == "" && f.typ == "" {
		return true
	}

	if f.server != "" {
		if msg.Server != f.server+":53" {
			return false
		}
	}
	if f.typ != "" {
		if msg.Msg.QuestionSec.Type != f.typ {
			return false
		}
	}

	return true
}
