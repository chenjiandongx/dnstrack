package codec

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

type Header struct {
	ID       uint16 `json:"id" yaml:"id"`
	Response bool   `json:"-" yaml:"-"`
}

type Question struct {
	Name string `json:"name" yaml:"name"`
	Type string `json:"type" yaml:"type"`
}

type Answer struct {
	Name   string `json:"name" yaml:"name"`
	Type   string `json:"type" yaml:"type"`
	TTL    uint32 `json:"ttl" yaml:"ttl"`
	Record string `json:"record" yaml:"record"`
}

type Authority struct {
	Name   string `json:"name" yaml:"name"`
	Type   string `json:"type" yaml:"type"`
	Record string `json:"record" yaml:"record"`
}

type Additional struct {
	Name   string `json:"name" yaml:"name"`
	Type   string `json:"type" yaml:"type"`
	Record string `json:"record" yaml:"record"`
}

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
4.1. Format

All communications inside of the domain protocol are carried in a single
format called a message.  The top level format of message is divided
into 5 sections (some of which are empty in certain cases) shown below:

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
*/

type Message struct {
	Header        Header       `json:"header" yaml:"header"`
	QuestionSec   Question     `json:"question" yaml:"question"`
	AnswerSec     []Answer     `json:"answer" yaml:"answer"`
	AuthoritySec  []Authority  `json:"authority" yaml:"authority"`
	AdditionalSec []Additional `json:"additional" yaml:"additional"`
}

type decoder struct {
	p dnsmessage.Parser
	b []byte
	m *Message
}

func Decode(b []byte) (*Message, error) {
	return newDecoder(b).decode()
}

func newDecoder(b []byte) *decoder {
	return &decoder{
		b: b,
		m: &Message{
			AnswerSec:     []Answer{},
			AuthoritySec:  []Authority{},
			AdditionalSec: []Additional{},
		},
	}
}

func (d *decoder) decode() (*Message, error) {
	states := []func() error{
		d.decodeHeader,
		d.decodeQuestion,
		d.decodeAnswer,
		d.decodeAuthority,
		d.decodeAdditional,
	}

	for _, f := range states {
		if err := f(); err != nil {
			return nil, err
		}
	}
	return d.m, nil
}

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
4.1.1. Header section format

The header contains the following fields:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

ID              A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.

QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:

                0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use

AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.

                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit
*/
// decodeHeader decodes header of dns packet
func (d *decoder) decodeHeader() error {
	header, err := d.p.Start(d.b)
	if err != nil {
		return err
	}

	d.m.Header = Header{
		ID:       header.ID,
		Response: header.Response,
	}
	return nil
}

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
4.1.2. Question section format

The question section is used to carry the "question" in most queries,
i.e., the parameters that define what is being asked.  The section
contains QDCOUNT (usually 1) entries, each of the following format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:
QNAME           a domain name represented as a sequence of labels, where
                each label consists of a length octet followed by that
                number of octets.  The domain name terminates with the
                zero length octet for the null label of the root.  Note
                that this field may be an odd number of octets; no
                padding is used.

QTYPE           a two octet code which specifies the type of the query.
                The values for this field include all codes valid for a
                TYPE field, together with some more general codes which
                can match more than one type of RR.
*/
// decodeQuestion decodes question section of dns packet
func (d *decoder) decodeQuestion() error {
	for {
		q, err := d.p.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}

		d.m.QuestionSec.Name = q.Name.String()
		d.m.QuestionSec.Type = q.Type.String()
		if err := d.p.SkipAllQuestions(); err != nil {
			return err
		}
		break
	}
	return nil
}

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
4.1.3. Resource record format

The answer, authority, and additional sections all share the same
format: a variable number of resource records, where the number of
records is specified in the corresponding count field in the header.
Each resource record has the following format:
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

NAME            a domain name to which this resource record pertains.

TYPE            two octets containing one of the RR type codes.  This
                field specifies the meaning of the data in the RDATA
                field.

CLASS           two octets which specify the class of the data in the
                RDATA field.

TTL             a 32 bit unsigned integer that specifies the time
                interval (in seconds) that the resource record may be
                cached before it should be discarded.  Zero values are
                interpreted to mean that the RR can only be used for the
                transaction in progress, and should not be cached.
*/
// parseResourceRecord parse resource records from dnsmessage.Type
func (d *decoder) parseResourceRecord(t dnsmessage.Type) (string, bool, error) {
	var unknown bool
	var s string
	switch t {
	case dnsmessage.TypeA:
		r, err := d.p.AResource()
		if err != nil {
			return "", unknown, err
		}
		s = ipString(r.A[:])

	case dnsmessage.TypeAAAA:
		r, err := d.p.AAAAResource()
		if err != nil {
			return "", unknown, err
		}
		s = ipString(r.AAAA[:])

	case dnsmessage.TypeCNAME:
		r, err := d.p.CNAMEResource()
		if err != nil {
			return "", unknown, err
		}
		s = r.CNAME.String()

	case dnsmessage.TypeMX:
		r, err := d.p.MXResource()
		if err != nil {
			return "", unknown, err
		}
		s = r.MX.String()

	case dnsmessage.TypePTR:
		r, err := d.p.PTRResource()
		if err != nil {
			return "", unknown, err
		}
		s = r.PTR.String()

	case dnsmessage.TypeSRV:
		r, err := d.p.SRVResource()
		if err != nil {
			return "", unknown, err
		}
		s = fmt.Sprintf("%s:%d/W:%d/P:%d", r.Target.String(), r.Port, r.Weight, r.Priority)

	case dnsmessage.TypeNS:
		r, err := d.p.NSResource()
		if err != nil {
			return "", unknown, err
		}
		s = r.NS.String()

	default:
		unknown = true
		_, _ = d.p.UnknownResource()
	}

	return s, unknown, nil
}

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
3.2.2. TYPE values

TYPE fields are used in resource records.  Note that these types are a
subset of QTYPEs.

TYPE            value and meaning
A               1 a host address
NS              2 an authoritative name server
MD              3 a mail destination (Obsolete - use MX)
MF              4 a mail forwarder (Obsolete - use MX)
CNAME           5 the canonical name for an alias
SOA             6 marks the start of a zone of authority
MB              7 a mailbox domain name (EXPERIMENTAL)
MG              8 a mail group member (EXPERIMENTAL)
MR              9 a mail rename domain name (EXPERIMENTAL)
NULL            10 a null RR (EXPERIMENTAL)
WKS             11 a well known service description
PTR             12 a domain name pointer
HINFO           13 host information
MINFO           14 mailbox or mail list information
MX              15 mail exchange
TXT             16 text strings
*/
// decodeAnswer decode answer section of dns packet
func (d *decoder) decodeAnswer() error {
	for {
		h, err := d.p.AnswerHeader()
		if err != nil || errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}

		answer := Answer{
			Name: h.Name.String(),
			TTL:  h.TTL,
			Type: h.Type.String(),
		}

		record, unknown, err := d.parseResourceRecord(h.Type)
		if err != nil {
			return err
		}
		if !unknown {
			answer.Record = record
			d.m.AnswerSec = append(d.m.AnswerSec, answer)
		}
	}
	return nil
}

// decodeAuthority decodes authority section of dns packet
func (d *decoder) decodeAuthority() error {
	for {
		h, err := d.p.AuthorityHeader()
		if err != nil || errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}

		record, unknown, err := d.parseResourceRecord(h.Type)
		if err != nil {
			return err
		}
		if !unknown {
			d.m.AuthoritySec = append(d.m.AuthoritySec, Authority{
				Name:   h.Name.String(),
				Type:   h.Type.String(),
				Record: record,
			})
		}
	}

	return nil
}

// decodeAdditional decode additional section of dns packet
func (d *decoder) decodeAdditional() error {
	for {
		h, err := d.p.Additional()
		if err != nil || errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}

		additional := Additional{
			Name: h.Header.Name.String(),
		}

		switch r := h.Body.(type) {
		case *dnsmessage.AResource:
			additional.Record = ipString(r.A[:])
			additional.Type = dnsmessage.TypeA.String()

		case *dnsmessage.AAAAResource:
			additional.Record = ipString(r.AAAA[:])
			additional.Type = dnsmessage.TypeAAAA.String()

		case *dnsmessage.CNAMEResource:
			additional.Record = r.CNAME.String()
			additional.Type = dnsmessage.TypeCNAME.String()

		case *dnsmessage.NSResource:
			additional.Record = r.NS.String()
			additional.Type = dnsmessage.TypeNS.String()
		}

		if additional.Type != "" {
			d.m.AdditionalSec = append(d.m.AdditionalSec, additional)
		}
	}

	return nil
}

func ipString(b []byte) string {
	return net.IP(b).String()
}
