package qlog

import (
	"context"

	"github.com/Berserk-Automation-Hub/quic-go-utls"
	"github.com/Berserk-Automation-Hub/quic-go-utls/qlog"
	"github.com/Berserk-Automation-Hub/quic-go-utls/qlogwriter"
)

const EventSchema = "urn:ietf:params:qlog:events:http3-12"

func DefaultConnectionTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracerWithSchemas(ctx, isClient, connID, []string{qlog.EventSchema, EventSchema})
}
