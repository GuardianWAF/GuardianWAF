package main

import (
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/challenge"
)

func setupChallengeService(cfg *config.Config, eng *engine.Engine) (*challenge.Service, error) {
	if !cfg.WAF.Challenge.Enabled {
		return nil, nil
	}

	chCfg := challenge.Config{
		Enabled:    true,
		Difficulty: cfg.WAF.Challenge.Difficulty,
		CookieTTL:  cfg.WAF.Challenge.CookieTTL,
		CookieName: cfg.WAF.Challenge.CookieName,
	}
	if cfg.WAF.Challenge.SecretKey != "" {
		chCfg.SecretKey = []byte(cfg.WAF.Challenge.SecretKey)
	}
	chCfg.ClientIPExtractor = eng.ExtractClientIP

	challengeSvc, err := challenge.NewService(chCfg)
	if err != nil {
		return nil, err
	}
	eng.SetChallengeService(challengeSvc)
	return challengeSvc, nil
}

func registerChallengeHandler(mux *http.ServeMux, challengeSvc *challenge.Service) {
	if challengeSvc == nil {
		return
	}
	mux.Handle(challenge.VerifyPath, challengeSvc.VerifyHandler())
}
