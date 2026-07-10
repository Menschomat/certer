package main

import "strings"

func normalizeURL(url string) string {
	if url == "" {
		return ""
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	return strings.TrimSuffix(url, "/")
}
