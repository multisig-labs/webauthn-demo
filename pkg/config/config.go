package config

import "github.com/AbsaOSS/env-binder/env"

type config struct {
	// Serve content from public not embedded
	DevMode bool `env:"DEV_MODE,default=false"`
}

var Env *config

func init() {
	Env = &config{}
	if err := env.Bind(Env); err != nil {
		panic(err)
	}
}
