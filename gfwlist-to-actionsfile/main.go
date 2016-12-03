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
	var (
		blacklistAddr string
		whitelistAddr string
	)
	flag.StringVar(&blacklistAddr, "-blacklist-forward", "127.0.0.1:8228", "blacklist forward address")
	flag.StringVar(&whitelistAddr, "-whitelist-forward", ".", "whitelist forward address")
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
		if len(line) == 0 {
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

	allrules = removeDuplicates(allrules)
	allrules = removeSubmatches(allrules)
	allexcepts = removeDuplicates(allexcepts)
	allexcepts = removeSubmatches(allexcepts)

	fmt.Println("{{alias}}")
	fmt.Printf("blacklist = +forward-override{forward %s}\n", blacklistAddr)
	fmt.Printf("whitelist = +forward-override{forward %s}\n", whitelistAddr)

	fmt.Println()
	fmt.Println("{blacklist}")
	for _, r := range allrules {
		fmt.Println(r)
	}

	fmt.Println()
	fmt.Println("{whitelist}")
	for _, r := range allexcepts {
		fmt.Println(r)
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
	} else if pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
		return
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
		if len(pattern) > 0 {
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
		} else if strings.Index(pattern, "/") < 0 {
			return
		} else {
			path = pattern
		}
	}
	if includesSubdomains && net.ParseIP(domain) == nil {
		domain = "." + domain
	}
	if len(path) > 0 {
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
			if len(domain) == 0 && strings.HasPrefix(path, "/") {
				path = "/(.*/)?" + path[1:]
			} else if len(path) > 0 && !strings.HasPrefix(path, "/") {
				if strings.HasPrefix(path, ".*") {
					path = "/" + path
				} else {
					path = "/.*" + path
				}
			}
		}
	}
	if len(domains) > 0 && len(domain) == 0 {
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
		if len(domain)+len(path) > 0 {
			if isException {
				excepts = append(excepts, domain+path)
			} else {
				rules = append(rules, domain+path)
			}
		}
	}
	return
}

func removeDuplicates(rules []string) []string {
	encountered := make(map[string]bool)
	number := 0
	for _, r := range rules {
		if !encountered[r] {
			encountered[r] = true
			rules[number] = r
			number++
		}
	}
	return rules[:number]
}

func removeSubmatches(rules []string) []string {
	encountered := make(map[string]bool)
	for _, r := range rules {
		if r[0] == '.' {
			encountered[r] = true
		}
	}

	number := 0
Outer:
	for _, r := range rules {
		if r[0] != '.' && encountered["."+r] {
			continue
		}
		arr := []string{r[1:]}
		pos := strings.Index(r, "/")
		if pos > 0 {
			arr = append(arr, r[:pos])
		}
		for _, s := range arr {
			for {
				pos := strings.IndexAny(s, "./")
				if pos < 0 || s[pos] != '.' {
					break
				}
				if encountered[s[pos:]] {
					continue Outer
				}
				s = s[pos+1:]
			}
		}
		rules[number] = r
		number++
	}
	return rules[:number]
}

var (
	regxIsDomain          = regexp.MustCompile(`[.:](?:\d+|a[cdefgilmorstuvz]|asia|b[adefghijnorstwyz]|biz|c[acdfghiklmnoruyz]|cat|city|club|com|d[ejkmoz]|e[cegstu]|edu|f[ijmr]|fit|g[adeghilmprty]|gov|h[knrtu]|i[edlmnoqrst]|info|j[emop]|k[eghirwz]|l[abikstuvy]|m[adegklmnstuvwxyz]|mil|mobi|n[aefgilopruz]|name|net|ninja|om|org|p[aeghklnrstwy]|press|pro|qa|r[osuw]|red|s[abceghiklmnortuv]|t[cdghjklmnortvwz]|today|u[agksyz]|v[ceginu]|ws|wang|wiki|work|xxx|xyz|z[amw])$`)
	regxSpecialCharacters = regexp.MustCompile("[.+?]")
)
