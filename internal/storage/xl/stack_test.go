package xl

import "runtime"

func runtimeStack(buf []byte) int { return runtime.Stack(buf, true) }
