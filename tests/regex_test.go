package tests

import (
	"regexp"
	"testing"
)

func Test_Regex(t *testing.T) {

	html := "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"UTF-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1, user-scalable=0\">\n    <link rel=\"shortcut icon\" href=\"data:image/x-icon;,\" type=\"image/x-icon\">\n    <title>minioidc</title>\n    <link rel=\"stylesheet\" type=\"text/css\" href=\"/static/styles.css\">\n</head>\n<body>\n    \n<form class=\"form\" method=\"post\">\n    <p class=\"error\">\n        \n        \n    </p>\n    <input name=\"username\" type=\"text\" placeholder=\"Username\" value=\"\" />\n    <input name=\"password\" type=\"password\" placeholder=\"Password\" />\n    <input type=\"hidden\" name=\"__csrf\" value=\"\">\n    <button type=\"submit\">Login</button>\n</form>\n\n</body>\n</html>\n"
	pattern := `<input[^>]+\bname="__csrf"[^>]*>`
	rexp := regexp.MustCompile(pattern)
	matches := rexp.FindStringSubmatch(html)
	if len(matches) != 1 {
		t.Fatalf("expected 1, got %d", len(matches))
	}

	rexp = regexp.MustCompile(`value="([^"]*)"`)
	matches = rexp.FindStringSubmatch(matches[0])
	if len(matches) != 2 {
		t.Fatalf("expected 2, got %d", len(matches))
	}

	t.Log(matches[1])
}
