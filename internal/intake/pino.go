package intake

import (
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

// pinoJoinWindow is how long a request may wait for its "request completed" line. A request id is reused when
// the process starts again ("req-1" after every start), so a completion long after the request is not joined.
const pinoJoinWindow = 10 * time.Minute

// joinSplitRequests joins the two lines that Fastify's logger writes for one request (pino-http, which nestjs-pino
// uses, writes one line and needs no join): "incoming request" with req.method, req.url and req.remoteAddress, and a later "request completed"
// with res.statusCode, both with the same reqId. The status is copied into the request line, which then is a
// request like any other (category webserver), so the web rules read it. Both lines stay events: nothing is
// removed, and the counts of the file do not change.
//
// Lines are joined only within one process (pid and hostname) and within pinoJoinWindow. A completion without a
// waiting request, or a request that never completes, is left as it was.
func joinSplitRequests(events []event.Event) {
	type key struct{ pid, host, id string }
	waiting := map[key]int{}

	for index := range events {
		fields := events[index].Fields
		id := fields["reqId"]
		if id == "" {
			continue
		}
		at := key{pid: fields["pid"], host: fields["hostname"], id: id}

		switch {
		case fields["req.method"] != "" && fields["req.url"] != "" && fields["res.statusCode"] == "" && fields[event.Status] == "":
			waiting[at] = index
		case fields["res.statusCode"] != "" && fields["req.method"] == "":
			request, found := waiting[at]
			if !found {
				continue
			}
			delete(waiting, at)
			if gap := events[index].Time.Sub(events[request].Time); gap < 0 || gap > pinoJoinWindow {
				continue
			}
			joined := events[request].Fields
			joined["res.statusCode"] = fields["res.statusCode"]
			if took := fields["responseTime"]; took != "" {
				joined["responseTime"] = took
			}
			joined["joined_from"] = events[index].Ref
			appFields(joined)
		}
	}
}
