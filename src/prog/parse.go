// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"strconv"
)

// LogEntry describes one program in execution log.
type LogEntry struct {
	Ps    []*Prog
	Proc  int // index of parallel proc
	Start int // start offset in log
	End   int // end offset in log
}

func (target *Target) ParseLog(data []byte) []*LogEntry {
	var entries []*LogEntry
	ent := &LogEntry{}
	var cur []byte
	faultCall, faultNth := -1, -1

	var progDatas [][]byte
	var inProgLogRange bool
	var faultCalls, faultNths []int

	for pos := 0; pos < len(data); {
		nl := bytes.IndexByte(data[pos:], '\n')
		if nl == -1 {
			nl = len(data) - 1
		} else {
			nl += pos
		}
		line := data[pos : nl+1]
		pos0 := pos
		pos = nl + 1

		if proc, ok := extractInt(line, "executing program "); ok {
			if len(progDatas) != 0 {
				//if ent.P != nil && len(ent.P.Calls) != 0 {
				ps, err := target.Deserialize(progDatas, NonStrict)
				if err != nil {
					continue
				}

				for idx, fc := range faultCalls {
					if fc >= 0 && fc < len(ps[idx].Calls) {
						// We add 1 because now the property is 1-based.
						//p.Calls[faultCall].Props.FailNth = faultNth + 1
						ps[idx].Calls[fc].Props.FailNth = faultNths[idx] + 1
					}
				}
				ent.Ps = ps
				ent.End = pos0
				entries = append(entries, ent)
				faultCall, faultNth = -1, -1
			}

			ent = &LogEntry{
				Proc:  proc,
				Start: pos0,
			}
			// We no longer print it this way, but we still parse such fragments to preserve
			// the backward compatibility.
			if parsedFaultCall, ok := extractInt(line, "fault-call:"); ok {
				faultCall = parsedFaultCall
				faultNth, _ = extractInt(line, "fault-nth:")
			}
			cur = nil
			inProgLogRange = true
			progDatas = nil
			faultCalls = nil
			faultNths = nil
			continue
		}
		if ent == nil {
			continue
		}

		res := bytes.Equal(line, []byte("end of program\n"))
		if res {
			inProgLogRange = false
			continue
		}

		if !inProgLogRange {
			continue
		}

		res = bytes.Equal(line, []byte("---\n"))
		if res {
			progDatas = append(progDatas, cur)
			faultCalls = append(faultCalls, faultCall)
			faultNths = append(faultNths, faultNth)
			cur = nil
			continue
		}
		cur = append(cur, line...)
	}

	if len(progDatas) != 0 {
		//if ent.P != nil && len(ent.P.Calls) != 0 {
		ps, err := target.Deserialize(progDatas, NonStrict)
		if err != nil {
			return entries
		}

		for idx, fc := range faultCalls {
			if fc >= 0 && fc < len(ps[idx].Calls) {
				// We add 1 because now the property is 1-based.
				//p.Calls[faultCall].Props.FailNth = faultNth + 1
				ps[idx].Calls[fc].Props.FailNth = faultNths[idx] + 1
			}
		}
		ent.Ps = ps
		ent.End = len(data)
		entries = append(entries, ent)
	}
	return entries
}

func extractInt(line []byte, prefix string) (int, bool) {
	pos := bytes.Index(line, []byte(prefix))
	if pos == -1 {
		return 0, false
	}
	pos += len(prefix)
	end := pos
	for end != len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}
	v, _ := strconv.Atoi(string(line[pos:end]))
	return v, true
}
