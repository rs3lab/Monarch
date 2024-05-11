// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	// Import all targets, so that users only need to import sys.
	_ "monarch/sys/akaros/gen"
	_ "monarch/sys/darwin/gen"
	_ "monarch/sys/freebsd/gen"
	_ "monarch/sys/fuchsia/gen"
	_ "monarch/sys/linux/gen"
	_ "monarch/sys/netbsd/gen"
	_ "monarch/sys/openbsd/gen"
	_ "monarch/sys/test/gen"
	_ "monarch/sys/trusty/gen"
	_ "monarch/sys/windows/gen"
)
