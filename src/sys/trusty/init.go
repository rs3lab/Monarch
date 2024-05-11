// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package trusty

import (
	"monarch/prog"
	"monarch/sys/targets"
)

func InitTarget(target *prog.Target) {
	target.MakeDataMmap = targets.MakeSyzMmap(target)
}
