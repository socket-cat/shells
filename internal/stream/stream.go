// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package stream implements a minimal VT/ANSI stream parser that watches a
// terminal byte stream for DECSET/DECRST private-mode changes (CSI ? ... h/l)
// and OSC 0/1/2 title sequences.
//
// Only the subset of escape sequences relevant to session bookkeeping is
// recognised; everything else is consumed and ignored so that the parser can
// run on a raw pty feed without disturbing it.
package stream

// Byte constants matching the JS source.
const (
	esc       byte = 0x1b
	csi       byte = 0x5b
	osc       byte = 0x5d
	bel       byte = 0x07
	question  byte = 0x3f
	semicolon byte = 0x3b
	h         byte = 0x68
	l         byte = 0x6c
	bslash    byte = 0x5c
	zero      byte = 0x30
	one       byte = 0x31
	two       byte = 0x32
	nine      byte = 0x39
)

// Parser states.
const (
	sGround = iota
	sEsc
	sCsiQ
	sCsiParam
	sOscType
	sOscSep
	sOscText
	sOscEsc
)

// ModeFunc is invoked for each DEC private mode toggle reported by the stream.
// mode is the numeric parameter (as a decimal string, e.g. "1049") and isSet
// is true for 'h' (set) and false for 'l' (reset).
type ModeFunc func(mode string, isSet bool)

// TitleFunc is invoked with the window title text from an OSC 0/1/2 sequence.
type TitleFunc func(title string)

// Parser scans a byte stream incrementally, reporting mode changes and titles.
type Parser struct {
	onMode  ModeFunc
	onTitle TitleFunc
	state   int
	param   []byte
	oscType byte
	oscText []byte
}

// New returns a parser that dispatches to the provided callbacks.
func New(onMode ModeFunc, onTitle TitleFunc) *Parser {
	return &Parser{onMode: onMode, onTitle: onTitle}
}

// Parse feeds the next chunk of bytes to the state machine and returns the
// length of the leading prefix of buf that ends on a clean boundary (i.e. the
// parser is back in the ground state after the last byte), so the caller can
// avoid replaying a chunk that starts mid-escape-sequence.
func (p *Parser) Parse(buf []byte) int {
	state := p.state
	lastGround := 0
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		switch state {
		case sGround:
			if b == esc {
				state = sEsc
			}
		case sEsc:
			switch {
			case b == csi:
				state = sCsiQ
			case b == osc:
				state = sOscType
				p.oscType = 0
				p.oscText = p.oscText[:0]
			case b == esc:
				state = sEsc
			default:
				state = sGround
			}
		case sCsiQ:
			switch {
			case b == question:
				state = sCsiParam
				p.param = p.param[:0]
			case b == esc:
				state = sEsc
			default:
				state = sGround
			}
		case sCsiParam:
			switch {
			case (b >= zero && b <= nine) || b == semicolon:
				if len(p.param) < 256 {
					p.param = append(p.param, b)
				}
			case b == h || b == l:
				isSet := b == h
				start := 0
				for j := 0; j <= len(p.param); j++ {
					if j == len(p.param) || p.param[j] == semicolon {
						if j > start {
							if p.onMode != nil {
								p.onMode(string(p.param[start:j]), isSet)
							}
						}
						start = j + 1
					}
				}
				p.param = p.param[:0]
				state = sGround
			case b == esc:
				p.param = p.param[:0]
				state = sEsc
			default:
				p.param = p.param[:0]
				state = sGround
			}
		case sOscType:
			switch {
			case b == zero || b == one || b == two:
				p.oscType = b
				state = sOscSep
			case b == esc:
				state = sEsc
			default:
				state = sGround
			}
		case sOscSep:
			switch {
			case b == semicolon:
				p.oscText = p.oscText[:0]
				state = sOscText
			case b == esc:
				state = sEsc
			default:
				state = sGround
			}
		case sOscText:
			switch {
			case b == bel:
				if p.oscType != 0 && p.onTitle != nil {
					p.onTitle(string(p.oscText))
				}
				p.oscText = p.oscText[:0]
				p.oscType = 0
				state = sGround
			case b == esc:
				state = sOscEsc
			default:
				if len(p.oscText) < 4096 {
					p.oscText = append(p.oscText, b)
				}
			}
		case sOscEsc:
			switch {
			case b == bslash:
				if p.oscType != 0 && p.onTitle != nil {
					p.onTitle(string(p.oscText))
				}
				p.oscText = p.oscText[:0]
				p.oscType = 0
				state = sGround
			case b == esc:
				if len(p.oscText) < 4096 {
					p.oscText = append(p.oscText, esc)
				}
				state = sOscEsc
			default:
				if len(p.oscText) < 4094 {
					p.oscText = append(p.oscText, esc)
					p.oscText = append(p.oscText, b)
				}
				state = sOscText
			}
		}
		if state == sGround {
			lastGround = i + 1
		}
	}
	p.state = state
	return lastGround
}
