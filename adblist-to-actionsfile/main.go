package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

func main() {
	flag.Parse()

	reader := os.Stdin

	if flag.NArg() > 0 {
		name := flag.Arg(0)
		file, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer file.Close()
		reader = file
	}

	allrules := make([]string, 0, 128)
	allexcepts := make([]string, 0, 64)

	s := bufio.NewScanner(reader)
	for s.Scan() {
		line := s.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case '[', '!':
		default:
			rules, excepts := parse(line)
			if len(rules) > 0 || len(excepts) > 0 {
				allrules = append(allrules, rules...)
				allexcepts = append(allexcepts, excepts...)
			} else {
				fmt.Fprintln(os.Stderr, "skip:", line)
				break
			}
		}
	}

	if len(allrules) > 0 {
		fmt.Println("{+block{}}")
		for _, r := range allrules {
			fmt.Println(r)
		}
		fmt.Println()
		fmt.Println("{-block}")
		for _, r := range allexcepts {
			fmt.Println(r)
		}
	}
}

func parse(pattern string) (rules, excepts []string) {
	if strings.Index(pattern, "##") > -1 || strings.Index(pattern, "#@#") > -1 {
		return
	}
	var domain, path string
	var domains []string
	var isException bool
	var isHTTPS bool
	var includesSubdomains bool
	var startsWithDomain bool
	if strings.HasPrefix(pattern, "@@") {
		pattern = pattern[2:]
		isException = true
	}
	if pattern[0] == '|' {
		if len(pattern) < 2 {
			return
		}
		if pattern[1] == '|' {
			pattern = pattern[2:]
			includesSubdomains = true
		} else if strings.HasPrefix(pattern, "|http://") {
			pattern = pattern[8:]
		} else if strings.HasPrefix(pattern, "|https://") {
			pattern = pattern[9:]
			isHTTPS = true
		} else {
			return
		}
		startsWithDomain = true
	} else if strings.HasPrefix(pattern, "http://") {
		pattern = pattern[7:]
		startsWithDomain = true
	} else if strings.HasPrefix(pattern, "https://") {
		pattern = pattern[8:]
		isHTTPS = true
		startsWithDomain = true
	}
	if pos := strings.IndexAny(pattern, "^/$"); pos > -1 {
		if prefix := pattern[:pos]; startsWithDomain || regxIsDomain.MatchString(prefix) {
			domain, pattern = prefix, pattern[pos:]
		}
		if pos = strings.Index(pattern, "$"); pos > -1 {
			path, pattern = pattern[:pos], pattern[pos+1:]
		} else {
			path, pattern = pattern, ""
		}
		if pattern != "" {
			if strings.Index(pattern, ",") > -1 {
				return
			}
			if !strings.HasPrefix(pattern, "domain=") {
				return
			}
			domains = strings.Split(pattern[7:], "|")
		}
	} else {
		if startsWithDomain || regxIsDomain.MatchString(pattern) {
			domain = pattern
		} else {
			path = pattern
		}
	}
	if includesSubdomains && net.ParseIP(regxDomainWithPort.ReplaceAllLiteralString(domain, "")) == nil {
		domain = "." + domain
	}
	if path != "" {
		if strings.HasPrefix(path, "^") {
			path = path[1:]
		}
		if strings.HasSuffix(path, "^") || strings.HasSuffix(path, "|") {
			path = path[:len(path)-1] + "$"
		} else if strings.HasSuffix(path, "*") {
			path = path[:len(path)-1]
		}
		if path == "/" {
			path = ""
		} else if isHTTPS {
			return
		} else {
			path = regxSpecialCharacters.ReplaceAllString(path, "\\$0")
			path = strings.Replace(path, "^", "\\b", -1)
			path = strings.Replace(path, "*", ".*", -1)
			if domain == "" && strings.HasPrefix(path, "/") {
				path = "/(.*/)?" + path[1:]
			} else if path != "" && !strings.HasPrefix(path, "/") {
				if strings.HasPrefix(path, ".*") {
					path = "/" + path
				} else {
					path = "/.*" + path
				}
			}
		}
	}
	if len(domains) > 0 && (domain == "" || domain == "*") {
		for _, dm := range domains {
			isexcept := isException
			if strings.HasPrefix(dm, "~") {
				dm = dm[1:]
				isexcept = true
			}
			if isexcept {
				if strings.HasPrefix(dm, "www.") || net.ParseIP(dm) != nil {
					excepts = append(excepts, dm+path)
				} else {
					excepts = append(excepts, "."+dm+path)
				}
			} else {
				if strings.HasPrefix(dm, "www.") || net.ParseIP(dm) != nil {
					rules = append(rules, dm+path)
				} else {
					rules = append(rules, "."+dm+path)
				}
			}
		}
	} else if len(domains) == 0 || !(strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".")) {
		if strings.HasPrefix(domain, "*") {
			domain = domain[1:]
		}
		if strings.HasSuffix(domain, "*") {
			domain = domain[:len(domain)-1]
		}
		if domain != "" || path != "" {
			if isException {
				excepts = append(excepts, domain+path)
			} else {
				rules = append(rules, domain+path)
			}
		}
	}
	return
}

var (
	regxDomainWithPort    = regexp.MustCompile(":[0-9*]+$")
	regxIsDomain          = regexp.MustCompile(`[.:](?:\d+|a[cdefgilmorstuvz]|asia|b[adefghijnorstwyz]|biz|c[acdfghiklmnoruyz]|cat|city|club|com|d[ejkmoz]|e[cegstu]|edu|f[ijmr]|fit|g[adeghilmprty]|gov|h[knrtu]|i[edlmnoqrst]|info|j[emop]|k[eghirwz]|l[abikstuvy]|m[adegklmnstuvwxyz]|mil|mobi|n[aefgilopruz]|name|net|ninja|om|org|p[aeghklnrstwy]|press|pro|qa|r[osuw]|red|s[abceghiklmnortuv]|t[cdghjklmnortvwz]|today|u[agksyz]|v[ceginu]|ws|wang|wiki|work|xxx|xyz|z[amw])$`)
	regxSpecialCharacters = regexp.MustCompile("[.+?]")
)
