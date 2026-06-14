package main

import (
	"io"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func setupAlertingRuntime(
	cfg *config.Config,
	eng *engine.Engine,
	eventBus *events.EventBus,
	eventStore events.EventStore,
	dash *dashboard.Dashboard,
	eventConsumerWG *sync.WaitGroup,
	stdin io.Reader,
	stdout io.Writer,
) *alerting.Manager {
	if cfg == nil || eng == nil || eventBus == nil || !cfg.Alerting.Enabled {
		return nil
	}
	targets := alertingWebhookTargets(cfg.Alerting.Webhooks)
	if len(targets) == 0 && len(cfg.Alerting.Emails) == 0 {
		return nil
	}

	alertMgr := alerting.NewManagerWithEmail(targets, cfg.Alerting.Emails)
	alertMgr.SetLogger(eng.Logs.Add)

	startEventConsumer(eventBus, eventConsumerWG, 256, func(event engine.Event) {
		alertMgr.HandleEvent(&event)
	})
	eng.Logs.Infof("Alerting enabled (%d webhooks, %d emails)", len(targets), len(cfg.Alerting.Emails))

	if dash != nil {
		dash.SetAlertingStatsFn(func() any { return alertMgr.GetStats() })
	}

	return alertMgr
}

func alertingWebhookTargets(webhooks []config.WebhookConfig) []alerting.WebhookTarget {
	targets := make([]alerting.WebhookTarget, 0, len(webhooks))
	for _, wc := range webhooks {
		targets = append(targets, alerting.WebhookTarget{
			Name:     wc.Name,
			URL:      wc.URL,
			Type:     wc.Type,
			Events:   wc.Events,
			MinScore: wc.MinScore,
			Cooldown: wc.Cooldown,
			Headers:  wc.Headers,
		})
	}
	return targets
}
