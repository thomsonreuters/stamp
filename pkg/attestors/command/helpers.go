// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package command

import "io"

type limitedWriter struct {
	w         io.Writer
	limit     int64
	written   int64
	truncated bool
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	// If we've already hit the limit, discard the data but report success
	// This prevents the command from blocking on output
	if lw.written >= lw.limit {
		lw.truncated = true
		return len(p), nil
	}

	// Calculate how much we can actually write
	remaining := lw.limit - lw.written
	toWrite := p
	if int64(len(p)) > remaining {
		toWrite = p[:remaining]
		lw.truncated = true
	}

	n, err := lw.w.Write(toWrite)
	lw.written += int64(n)

	if lw.truncated {
		return len(p), nil
	}

	return n, err
}
