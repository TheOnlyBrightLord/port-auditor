package embedconfig

import _ "embed"

//go:embed default.yaml
var DefaultConfig []byte
