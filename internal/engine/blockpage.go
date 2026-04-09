package engine

import (
	"html"
	"strings"
)

// blockPage generates a branded HTML block page for 403 responses.
func blockPage(requestID string, score int) string {
	var b strings.Builder
	b.Grow(2048)

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>403 Blocked — GuardianWAF</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;
min-height:100vh}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:48px;
max-width:520px;width:90%;text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
.shield{font-size:3rem;margin-bottom:16px}
h1{font-size:1.5rem;margin-bottom:8px;color:#f8fafc}
.code{font-size:4rem;font-weight:700;color:#ef4444;margin-bottom:8px;line-height:1}
.msg{color:#94a3b8;margin-bottom:24px;font-size:.9rem;line-height:1.5}
.details{background:#0f172a;border-radius:8px;padding:16px;text-align:left;font-size:.8rem;
color:#64748b;font-family:'SF Mono',Consolas,monospace}
.details span{color:#94a3b8}
.footer{margin-top:24px;font-size:.75rem;color:#475569}
</style>
</head>
<body>
<div class="card">
<div class="shield">&#128737;</div>
<div class="code">403</div>
<h1>Request Blocked</h1>
<p class="msg">Your request has been blocked by the web application firewall.<br>
If you believe this is an error, please contact the site administrator.</p>
<div class="details">`)

	b.WriteString(`<div>Request ID: <span>`)
	b.WriteString(html.EscapeString(requestID))
	b.WriteString(`</span></div>`)

	if score > 0 {
		b.WriteString(`<div>Threat Score: <span>`)
		b.WriteString(itoa(score))
		b.WriteString(`/100</span></div>`)
	}

	b.WriteString(`</div>
<div class="footer">Protected by GuardianWAF</div>
</div>
</body>
</html>`)

	return b.String()
}

// itoa converts an int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
