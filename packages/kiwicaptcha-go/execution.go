package kiwicaptcha

// Execution challenge program shape parsing. The wire blob is base64
// of a compact program: format byte, scope, action, op version, op
// count, then the op records. This file implements the exact program
// language accepted by the php ExecutionChallengeGenerator decode, so
// the record parser and the verifier can validate a stored program's
// shape and reject foreign blobs fail closed.
//
// Out of scope, deliberately: the trace simulator and the trace replay
// walker that verify a presented execution digest. See the package
// package documentation for the scope statement. A program parsed
// shape validated, and its signed commitment can still be checked
// against the stored bytes.

// Execution program language bounds.
const (
	ExecutionFormatVersion = 1
	ExecutionMinOps        = 8
	ExecutionMaxOps        = 24
	MaxProgramBase64       = 4096
	executionOpcodeCount   = 50
)

// Execution opcodes, in vocabulary order.
const (
	opAdd = iota
	opSub
	opMul
	opXor
	opAnd
	opOr
	opShl
	opShr
	opU8Create
	opU8Write
	opU8Read
	opU8Rotate
	opStrLen
	opStrCharcode
	opStrCodepoint
	opStrSlice
	opDomCreate
	opDomSetAttr
	opDomAppend
	opDomQuery
	opDomGetAttr
	opDomDatasetSet
	opDomDatasetGet
	opDomClassAdd
	opDomClassContains
	opDomParent
	opDomDispatch
	opDomSerialize
	opDomQueryReal
	opDomGeometry
	opDomPoint
	opDomEventReal
	opDomSerializeReal
	opDomObserve
	opDomSiblingIndex
	opDomChild
	opDomDepth
	opDomFragmentAppend
	opDomClone
	opDomReparent
	opDomAttrReflect
	opDomEventPhase
	opDomURLCanon
	opDomTextMutate
	opDomSelectDep
	opCssGeom
	opMutOrder
	opEvPhaseFull
	opRangeOrder
	opIntObs
)

// Per-version opcode ceilings of the execution grammar.
var executionMaxOpcodeByVersion = map[byte]int{
	1: 33,
	2: 34,
	3: 35,
	4: 37,
	5: 45,
	6: executionOpcodeCount,
}

type programCursor struct {
	data []byte
	pos  int
}

func (c *programCursor) read(n int) ([]byte, bool) {
	if n < 0 || c.pos+n > len(c.data) {
		return nil, false
	}
	out := c.data[c.pos : c.pos+n]
	c.pos += n
	return out, true
}

func (c *programCursor) readByte() (byte, bool) {
	raw, ok := c.read(1)
	if !ok {
		return 0, false
	}
	return raw[0], true
}

// readBoundedString reads one length prefixed string with the given
// inclusive bounds on the length byte.
func (c *programCursor) readBoundedString(minLen, maxLen int) bool {
	length, ok := c.readByte()
	if !ok {
		return false
	}
	if int(length) < minLen || int(length) > maxLen {
		return false
	}
	_, ok = c.read(int(length))
	return ok
}

// readID reads one identifier operand: a 4..16 length prefixed byte
// string.
func (c *programCursor) readID() bool {
	return c.readBoundedString(4, 16)
}

// readString reads one value operand: a 1..16 length prefixed byte
// string.
func (c *programCursor) readString() bool {
	return c.readBoundedString(1, 16)
}

// readValue reads one value operand with the 1..32 bound.
func (c *programCursor) readValue() bool {
	return c.readBoundedString(1, 32)
}

// readClass reads one class name operand with the 1..12 bound.
func (c *programCursor) readClass() bool {
	return c.readBoundedString(1, 12)
}

// skipByte consumes and discards one operand byte.
func (c *programCursor) skipByte() bool {
	_, ok := c.readByte()
	return ok
}

// readOperands consumes one opcode's operands and reports whether the
// encoding is inside the language. The modulo folds of the php reader
// never change the consumed width, so only the width matters here.
// The branch order mirrors the php operand reader one to one.
func (c *programCursor) readOperands(opcode int) bool {
	switch opcode {
	case opAdd, opSub, opMul, opXor, opAnd, opOr, opShl, opShr:
		_, ok := c.read(8)
		return ok
	case opU8Create:
		_, ok := c.readByte()
		return ok
	case opU8Write:
		_, ok := c.read(2)
		return ok
	case opU8Read, opU8Rotate:
		_, ok := c.readByte()
		return ok
	case opStrLen, opDomDatasetGet:
		return c.readString()
	case opStrCharcode, opStrCodepoint:
		return c.readString() && c.skipByte()
	case opStrSlice:
		if !c.readString() {
			return false
		}
		_, ok := c.read(2)
		return ok
	case opDomCreate, opDomChild:
		// Both read one tag byte and one identifier, in that order.
		return c.skipByte() && c.readID()
	case opDomSetAttr:
		// The php reader pairs the name byte with a value operand
		// (1..32), not a string operand (1..16).
		return c.skipByte() && c.readValue()
	case opDomQuery:
		return c.readID()
	case opDomGetAttr, opDomAttrReflect:
		_, ok := c.readByte()
		return ok
	case opDomDatasetSet:
		keyByte, ok := c.readByte()
		if !ok || keyByte < 1 || keyByte > 16 {
			return false
		}
		if _, ok := c.read(int(keyByte)); !ok {
			return false
		}
		return c.readValue()
	case opDomClassAdd, opDomClassContains:
		return c.readClass()
	case opDomAppend, opDomParent, opDomDispatch, opDomSerialize, opDomSerializeReal, opDomURLCanon:
		return true
	case opDomQueryReal, opDomGeometry, opDomEventReal, opDomSiblingIndex, opDomDepth:
		return c.readID()
	case opDomPoint:
		_, ok := c.read(2)
		return ok
	case opDomObserve:
		return c.readID() && c.skipByte()
	case opDomClone, opDomReparent:
		return c.readID() && c.skipByte()
	case opDomFragmentAppend:
		_, ok := c.read(2)
		return ok
	case opDomEventPhase:
		_, ok := c.readByte()
		return ok
	case opDomTextMutate:
		return c.readValue() && c.skipByte()
	case opDomSelectDep:
		_, ok := c.read(3)
		return ok
	case opCssGeom, opIntObs:
		// Version-6 real-platform probes: the probed id plus one raw
		// seed byte and one raw dst cell byte.
		if !c.readID() {
			return false
		}
		_, ok := c.read(2)
		return ok
	case opMutOrder, opRangeOrder:
		// Two raw bytes and the dst cell after the probed id.
		if !c.readID() {
			return false
		}
		_, ok := c.read(3)
		return ok
	case opEvPhaseFull:
		return c.readID() && c.skipByte()
	default:
		return false
	}
}

// DecodeExecutionProgram parses a program blob and reports whether it
// sits inside the protocol program language. A valid prefix with
// trailing bytes is rejected, every version bounds its own opcode
// space, and the identifiers follow the narrow deployment alphabet.
func DecodeExecutionProgram(programB64 string) bool {
	if programB64 == "" || len(programB64) > MaxProgramBase64 {
		return false
	}
	decoded, ok := b64CanonicalDecode(programB64)
	if !ok {
		return false
	}
	cur := &programCursor{data: decoded}
	header, ok := cur.readByte()
	if !ok || header != ExecutionFormatVersion {
		return false
	}
	scopeLen, ok := cur.readByte()
	if !ok {
		return false
	}
	scopeRaw, ok := cur.read(int(scopeLen))
	if !ok || len(scopeRaw) == 0 || len(scopeRaw) > 128 {
		return false
	}
	if !IsValidIdentifier(string(scopeRaw), 128) {
		return false
	}
	actionLen, ok := cur.readByte()
	if !ok {
		return false
	}
	actionRaw, ok := cur.read(int(actionLen))
	if !ok || len(actionRaw) == 0 || len(actionRaw) > 32 {
		return false
	}
	if !IsValidIdentifier(string(actionRaw), 32) {
		return false
	}
	opVersion, ok := cur.readByte()
	if !ok || opVersion < 1 || opVersion > MaxExecutionVersion {
		return false
	}
	opCount, ok := cur.readByte()
	if !ok || opCount < ExecutionMinOps || opCount > ExecutionMaxOps {
		return false
	}
	maxOpcode, ok := executionMaxOpcodeByVersion[opVersion]
	if !ok {
		return false
	}
	for i := 0; i < int(opCount); i++ {
		opcode, ok := cur.readByte()
		if !ok || int(opcode) >= maxOpcode {
			return false
		}
		if !cur.readOperands(int(opcode)) {
			return false
		}
	}
	return cur.pos == len(decoded)
}

// IsValidExecutionProgram reports whether the blob is inside the
// protocol program language.
func IsValidExecutionProgram(programB64 string) bool {
	return DecodeExecutionProgram(programB64)
}
