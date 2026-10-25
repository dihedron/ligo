package regexpolicy

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The narrowing check fails closed: each of these errors means "not a
// narrowing" (§3.10 rule 1).
var (
	ErrNotAnchored = errors.New("regex must start with ^ and end with an unescaped $")
	ErrUnsupported = errors.New("regex uses a construct the narrowing check does not support")
	ErrUndecided   = errors.New("regex pair exceeds the narrowing state budget")
)

// Narrowing is the result of CheckNarrowing.
type Narrowing struct {
	// Narrower reports whether every identity matched by the proposed regex
	// is matched by the current one.
	Narrower bool
	// Witness is, when Narrower is false, a shortest identity matched by the
	// proposed regex and not by the current one (§3.10 rule 2).
	Witness string
	// States is the number of product states explored.
	States int
}

// CheckNarrowing decides L(proposed) ⊆ L(current) for two regexes that passed
// the Appendix A validator, exploring at most limit product states
// (Appendix D.3).
func CheckNarrowing(current, proposed string, limit int) (Narrowing, error) {
	pn, err := compileForNarrowing(proposed)
	if err != nil {
		return Narrowing{}, fmt.Errorf("new regex: %w", err)
	}
	pw, err := compileForNarrowing(current)
	if err != nil {
		return Narrowing{}, fmt.Errorf("current regex: %w", err)
	}
	return include(pn, pw, limit)
}

func compileForNarrowing(expr string) (*syntax.Prog, error) {
	if !strings.HasPrefix(expr, "^") || !strings.HasSuffix(expr, "$") || strings.HasSuffix(expr, `\$`) {
		return nil, ErrNotAnchored
	}
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, err
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, err
	}
	for i := range prog.Inst {
		in := &prog.Inst[i]
		switch in.Op {
		case syntax.InstRune, syntax.InstRune1:
			if syntax.Flags(in.Arg)&syntax.FoldCase != 0 { //nolint:gosec // regexp/syntax stores the flags in Arg
				return nil, fmt.Errorf("%w: case-insensitive matching", ErrUnsupported)
			}
		case syntax.InstEmptyWidth:
			if emptyOp(in)&^(syntax.EmptyBeginText|syntax.EmptyEndText) != 0 {
				return nil, fmt.Errorf("%w: only ^ and $ are allowed as assertions", ErrUnsupported)
			}
		case syntax.InstAlt, syntax.InstAltMatch, syntax.InstCapture, syntax.InstNop,
			syntax.InstRuneAny, syntax.InstRuneAnyNotNL, syntax.InstMatch, syntax.InstFail:
		default: // an instruction kind this check does not know (EXT-19): fail closed
			return nil, fmt.Errorf("%w: instruction %v", ErrUnsupported, in.Op)
		}
	}
	return prog, nil
}

// endMode decides what a closure does with $ assertions.
type endMode int

const (
	endBlock endMode = iota // the input goes on: $ fails
	endPass                 // the input ends here: $ holds
	endKeep                 // undecided: keep the assertion for acceptsAtEnd
)

// closure returns the sorted set of consuming or match instructions reachable
// from pcs through empty transitions; atStart and atEnd decide ^ and $.
func closure(p *syntax.Prog, pcs []uint32, atStart, atEnd bool) []uint32 {
	if atEnd {
		return follow(p, pcs, atStart, endPass)
	}
	return follow(p, pcs, atStart, endBlock)
}

// frontierClose is closure with atEnd false, except that blocked $
// assertions are kept in the set, so that acceptsAtEnd can resume them.
func frontierClose(p *syntax.Prog, pcs []uint32, atStart bool) []uint32 {
	return follow(p, pcs, atStart, endKeep)
}

// follow walks the empty transitions from pcs.
func follow(p *syntax.Prog, pcs []uint32, atStart bool, end endMode) []uint32 {
	seen := make(map[uint32]bool)
	var out []uint32
	stack := append([]uint32(nil), pcs...)
	for len(stack) > 0 {
		pc := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		next, keep := emptyStep(&p.Inst[pc], atStart, end)
		if keep {
			out = append(out, pc)
		}
		stack = append(stack, next...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// emptyStep returns where the empty transitions of in lead, and whether in
// itself belongs to the closed set (consuming and match instructions, and $
// kept with endKeep).
func emptyStep(in *syntax.Inst, atStart bool, end endMode) (next []uint32, keep bool) {
	switch in.Op {
	case syntax.InstAlt, syntax.InstAltMatch:
		return []uint32{in.Out, in.Arg}, false
	case syntax.InstCapture, syntax.InstNop:
		return []uint32{in.Out}, false
	case syntax.InstEmptyWidth:
		op := emptyOp(in)
		if op&syntax.EmptyBeginText != 0 && !atStart {
			return nil, false
		}
		if op&syntax.EmptyEndText != 0 && end != endPass {
			return nil, end == endKeep // resumed only at end of input
		}
		return []uint32{in.Out}, false
	case syntax.InstFail:
		return nil, false
	}
	return nil, true // InstRune*, InstMatch
}

// emptyOp returns the assertion of an InstEmptyWidth instruction.
func emptyOp(in *syntax.Inst) syntax.EmptyOp {
	return syntax.EmptyOp(in.Arg) //nolint:gosec // regexp/syntax stores the EmptyOp in Arg
}

// startPC returns the start instruction, an index into p.Inst.
func startPC(p *syntax.Prog) uint32 {
	return uint32(p.Start) //nolint:gosec // bounded by len(p.Inst), which instruction indices (uint32) address
}

// step consumes rune r from a closed set, returning the next frontier.
func step(p *syntax.Prog, closed []uint32, r rune) []uint32 {
	var next []uint32
	for _, pc := range closed {
		if in := &p.Inst[pc]; matchesRune(in, r) {
			next = append(next, in.Out)
		}
	}
	return next
}

func matchesRune(in *syntax.Inst, r rune) bool {
	switch in.Op {
	case syntax.InstRune1:
		return r == in.Rune[0]
	case syntax.InstRune:
		return in.MatchRune(r)
	case syntax.InstRuneAny:
		return true
	case syntax.InstRuneAnyNotNL:
		return r != '\n'
	}
	return false
}

// classes partitions the rune space into intervals on which every consuming
// instruction of both programs behaves the same, and returns the lowest
// valid rune of each interval.
func classes(progs ...*syntax.Prog) []rune {
	cuts := map[rune]bool{0: true}
	for _, p := range progs {
		for i := range p.Inst {
			for _, r := range cutPoints(&p.Inst[i]) {
				if r >= 0 && r <= unicode.MaxRune {
					cuts[r] = true
				}
			}
		}
	}
	return representatives(cuts)
}

// representatives returns the lowest valid rune of each interval starting at
// a cut point.
func representatives(cuts map[rune]bool) []rune {
	reps := make([]rune, 0, len(cuts)+1)
	surrogate := false
	for r := range cuts {
		if r >= 0xD800 && r <= 0xDFFF {
			surrogate = true // not valid in a SPIFFE ID: the interval starts at U+E000
			continue
		}
		reps = append(reps, r)
	}
	if surrogate && !cuts[0xE000] {
		reps = append(reps, 0xE000)
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i] < reps[j] })
	return slices.DeleteFunc(reps, func(r rune) bool { return !utf8.ValidRune(r) })
}

// cutPoints returns the bounds of the rune ranges an instruction consumes:
// where the instruction starts or stops matching.
func cutPoints(in *syntax.Inst) []rune {
	switch in.Op {
	case syntax.InstRune1:
		return []rune{in.Rune[0], in.Rune[0] + 1}
	case syntax.InstRune:
		if len(in.Rune) == 1 {
			return []rune{in.Rune[0], in.Rune[0] + 1}
		}
		var out []rune
		for j := 0; j+1 < len(in.Rune); j += 2 {
			out = append(out, in.Rune[j], in.Rune[j+1]+1)
		}
		return out
	case syntax.InstRuneAnyNotNL:
		return []rune{'\n', '\n' + 1}
	}
	return nil
}

// productNode is a state of the product exploration: the frontier-closed
// sets of both programs, and the rune that led to it from its parent.
type productNode struct {
	n, w    []uint32
	atStart bool
	parent  int
	r       rune
}

// product is the breadth-first exploration of the product of two programs.
type product struct {
	pn, pw *syntax.Prog
	reps   []rune
	nodes  []productNode
	seen   map[string]bool
}

// include explores the product of the two programs breadth first, so the
// first state accepted by pn and not by pw gives a shortest witness.
func include(pn, pw *syntax.Prog, limit int) (Narrowing, error) {
	start := productNode{
		n:       frontierClose(pn, []uint32{startPC(pn)}, true),
		w:       frontierClose(pw, []uint32{startPC(pw)}, true),
		atStart: true,
		parent:  -1,
	}
	x := &product{pn: pn, pw: pw, reps: classes(pn, pw), nodes: []productNode{start}, seen: map[string]bool{key(start.n, start.w, true): true}}
	for i := 0; i < len(x.nodes); i++ {
		cur := x.nodes[i]
		if acceptsAtEnd(pn, cur.n, cur.atStart) && !acceptsAtEnd(pw, cur.w, cur.atStart) {
			return Narrowing{Witness: x.witness(i), States: len(x.nodes)}, nil
		}
		if len(cur.n) == 0 {
			continue // the new regex is dead: nothing more it can accept
		}
		if !x.expand(i, limit) {
			return Narrowing{States: len(x.nodes)}, ErrUndecided
		}
	}
	return Narrowing{Narrower: true, States: len(x.nodes)}, nil
}

// expand adds the unseen successors of node i on every representative rune;
// it returns false when the state budget is exceeded.
func (x *product) expand(i, limit int) bool {
	cur := x.nodes[i]
	for _, r := range x.reps {
		sn := step(x.pn, cur.n, r)
		if len(sn) == 0 {
			continue
		}
		nn := frontierClose(x.pn, sn, false)
		nw := frontierClose(x.pw, step(x.pw, cur.w, r), false)
		k := key(nn, nw, false)
		if x.seen[k] {
			continue
		}
		x.seen[k] = true
		x.nodes = append(x.nodes, productNode{n: nn, w: nw, parent: i, r: r})
		if len(x.nodes) > limit {
			return false
		}
	}
	return true
}

// witness returns the runes on the path from the start to node i.
func (x *product) witness(i int) string {
	var rs []rune
	for ; x.nodes[i].parent >= 0; i = x.nodes[i].parent {
		rs = append(rs, x.nodes[i].r)
	}
	slices.Reverse(rs)
	return string(rs)
}

// acceptsAtEnd reports whether a frontier-closed set reaches Match when the
// input ends here, resuming blocked $ assertions.
func acceptsAtEnd(p *syntax.Prog, set []uint32, atStart bool) bool {
	var resume []uint32
	for _, pc := range set {
		switch p.Inst[pc].Op {
		case syntax.InstMatch:
			return true
		case syntax.InstEmptyWidth:
			resume = append(resume, pc)
		}
	}
	for _, pc := range closure(p, resume, atStart, true) {
		if p.Inst[pc].Op == syntax.InstMatch {
			return true
		}
	}
	return false
}

// key canonicalizes a product state; the sets are sorted and free of
// duplicates.
func key(n, w []uint32, atStart bool) string {
	var b strings.Builder
	if atStart {
		b.WriteByte('S')
	}
	for _, pc := range n {
		fmt.Fprintf(&b, "%d,", pc)
	}
	b.WriteByte('|')
	for _, pc := range w {
		fmt.Fprintf(&b, "%d,", pc)
	}
	return b.String()
}
