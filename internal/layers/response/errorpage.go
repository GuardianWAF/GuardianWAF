package response

import (
	"fmt"
	"net/http"
	"strings"
)

// ErrorPage generates an HTML error response page.
// In "production" mode it shows a clean, safe page with no internal details.
// In "development" mode it includes additional diagnostic information.
func ErrorPage(statusCode int, mode string) string {
	if mode == "production" {
		return productionErrorPage(statusCode)
	}
	return developmentErrorPage(statusCode, "")
}

// ErrorPageWithDetails generates an error page with optional detail text.
// Details are only shown in development mode.
func ErrorPageWithDetails(statusCode int, mode, details string) string {
	if mode == "production" {
		return productionErrorPage(statusCode)
	}
	return developmentErrorPage(statusCode, details)
}

// statusText returns a user-friendly status message.
func statusText(code int) string {
	text := http.StatusText(code)
	if text == "" {
		text = "Error"
	}
	return text
}

// statusMessage returns a user-friendly explanation for common error codes.
func statusMessage(code int) string {
	switch code {
	case 400:
		return "The request could not be understood by the server."
	case 403:
		return "Access to this resource has been denied by the security policy."
	case 404:
		return "The requested resource could not be found."
	case 405:
		return "The request method is not allowed for this resource."
	case 408:
		return "The server timed out waiting for the request."
	case 413:
		return "The request payload is too large."
	case 429:
		return "Too many requests. Please slow down and try again later."
	case 500:
		return "An internal error occurred. Please try again later."
	case 502:
		return "The server received an invalid response from an upstream server."
	case 503:
		return "The service is temporarily unavailable. Please try again later."
	default:
		return "An error occurred while processing your request."
	}
}

// productionErrorPage generates a clean error page with no internal details.
func productionErrorPage(code int) string {
	title := statusText(code)
	message := statusMessage(code)

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString(fmt.Sprintf("<title>%d %s</title>\n", code, title))
	b.WriteString("<style>\n")
	b.WriteString("body{font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;")
	b.WriteString("background:#f5f5f5;color:#333;display:flex;justify-content:center;align-items:center;")
	b.WriteString("min-height:100vh;margin:0;}\n")
	b.WriteString(".container{text-align:center;padding:40px;background:#fff;border-radius:8px;")
	b.WriteString("box-shadow:0 2px 8px rgba(0,0,0,0.1);max-width:500px;}\n")
	b.WriteString(".code{font-size:72px;font-weight:bold;color:#e74c3c;margin:0;}\n")
	b.WriteString(".title{font-size:24px;margin:10px 0;color:#555;}\n")
	b.WriteString(".message{color:#777;margin:15px 0;}\n")
	b.WriteString(".brand{margin-top:30px;font-size:12px;color:#aaa;}\n")
	b.WriteString("</style>\n</head>\n<body>\n")
	b.WriteString("<div class=\"container\">\n")
	b.WriteString(fmt.Sprintf("<p class=\"code\">%d</p>\n", code))
	b.WriteString(fmt.Sprintf("<h1 class=\"title\">%s</h1>\n", escapeHTML(title)))
	b.WriteString(fmt.Sprintf("<p class=\"message\">%s</p>\n", escapeHTML(message)))
	b.WriteString("<p class=\"brand\">Protected by GuardianWAF</p>\n")
	b.WriteString("</div>\n</body>\n</html>")

	return b.String()
}

// developmentErrorPage generates an error page with diagnostic information.
func developmentErrorPage(code int, details string) string {
	title := statusText(code)
	message := statusMessage(code)

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString(fmt.Sprintf("<title>%d %s - Development</title>\n", code, title))
	b.WriteString("<style>\n")
	b.WriteString("body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:20px;}\n")
	b.WriteString(".header{border-bottom:2px solid #e74c3c;padding-bottom:10px;margin-bottom:20px;}\n")
	b.WriteString(".code{font-size:48px;color:#e74c3c;}\n")
	b.WriteString(".details{background:#16213e;padding:20px;border-radius:4px;")
	b.WriteString("border-left:4px solid #e74c3c;margin:15px 0;white-space:pre-wrap;}\n")
	b.WriteString(".warning{background:#f39c12;color:#000;padding:10px;border-radius:4px;")
	b.WriteString("margin-top:20px;font-weight:bold;}\n")
	b.WriteString(".brand{margin-top:20px;color:#555;}\n")
	b.WriteString("</style>\n</head>\n<body>\n")
	b.WriteString("<div class=\"header\">\n")
	b.WriteString(fmt.Sprintf("<span class=\"code\">%d</span> %s\n", code, escapeHTML(title)))
	b.WriteString("</div>\n")
	b.WriteString(fmt.Sprintf("<p>%s</p>\n", escapeHTML(message)))
	if details != "" {
		b.WriteString("<div class=\"details\">")
		b.WriteString(escapeHTML(details))
		b.WriteString("</div>\n")
	}
	b.WriteString("<div class=\"warning\">This is a development error page. Do not expose in production.</div>\n")
	b.WriteString("<p class=\"brand\">GuardianWAF Development Mode</p>\n")
	b.WriteString("</body>\n</html>")

	return b.String()
}

// escapeHTML escapes special HTML characters to prevent injection.
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
