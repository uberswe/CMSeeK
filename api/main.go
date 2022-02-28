package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	middlewareGin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"
)

func main() {
	r := gin.Default()

	r.Use(throttle(10))
	r.Use(auth)

	r.GET("/api/v1.0/cms/:domain", Domain)

	err := r.Run(":8080")
	if err != nil {
		log.Fatal("Failed to run server ", err)
		return
	}
}

func Domain(c *gin.Context) {
	d := c.Param("domain")

	err := checkDomain(d)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, "invalid domain")
		return
	}

	cmd := exec.Command("python", "cmseek.py", "-u", fmt.Sprintf("https://%s", d), "--follow-redirect", "--user-agent", fmt.Sprintf("Domaner.xyz Analysis Bot - Please contact support@domaner.xyz regarding any abuse or problem. Visit https://www.domaner.xyz/domains/%s for more information", d))
	b := new(strings.Builder)
	cmd.Stdout = b

	err = cmd.Run()

	if err != nil {
		log.Println(b.String())
		log.Println(err)
		c.JSON(http.StatusBadRequest, "could not query domain")
		return
	}

	// results are stored in /app/Result/{domain}/cms.json
	// Json file example
	// {
	//    "cms_id": "wp",
	//    "cms_name": "WordPress",
	//    "cms_url": "https://wordpress.org",
	//    "detection_param": "header",
	//    "last_scanned": "2022-02-27 17:44:17.602201",
	//    "url": "https://ma.rkus.io",
	//    "wp_license": "https://ma.rkus.io/license.txt",
	//    "wp_readme_file": "https://ma.rkus.io/readme.html",
	//    "wp_themes": "ma-rkus-io Version 5.9.1,",
	//    "wp_users": "markus,"
	// }

	if _, err = os.Stat(fmt.Sprintf("/app/Result/%s/cms.json", d)); errors.Is(err, os.ErrNotExist) {
		log.Println(b.String())
		log.Println(err)
		c.JSON(http.StatusBadRequest, "could not query domain")
		return
	}

	dat, err2 := os.ReadFile(fmt.Sprintf("/app/Result/%s/cms.json", d))
	if err2 != nil {
		log.Println(b.String())
		log.Println(err2)
		c.JSON(http.StatusBadRequest, "could not query domain")
		return
	}

	c.Data(http.StatusOK, "application/json", dat)
}

func checkDomain(name string) error {
	switch {
	case len(name) == 0:
		return nil // an empty domain name will result in a cookie without a domain restriction
	case len(name) > 255:
		return fmt.Errorf("cookie domain: name length is %d, can't exceed 255", len(name))
	}
	var l int
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			// check domain labels validity
			switch {
			case i == l:
				return fmt.Errorf("cookie domain: invalid character '%c' at offset %d: label can't begin with a period", b, i)
			case i-l > 63:
				return fmt.Errorf("cookie domain: byte length of label '%s' is %d, can't exceed 63", name[l:i], i-l)
			case name[l] == '-':
				return fmt.Errorf("cookie domain: label '%s' at offset %d begins with a hyphen", name[l:i], l)
			case name[i-1] == '-':
				return fmt.Errorf("cookie domain: label '%s' at offset %d ends with a hyphen", name[l:i], l)
			}
			l = i + 1
			continue
		}
		// test label character validity, note: tests are ordered by decreasing validity frequency
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b >= 'A' && b <= 'Z') {
			// show the printable unicode character starting at byte offset i
			c, _ := utf8.DecodeRuneInString(name[i:])
			if c == utf8.RuneError {
				return fmt.Errorf("cookie domain: invalid rune at offset %d", i)
			}
			return fmt.Errorf("cookie domain: invalid character '%c' at offset %d", c, i)
		}
	}
	// check top level domain validity
	switch {
	case l == len(name):
		return fmt.Errorf("cookie domain: missing top level domain, domain can't end with a period")
	case len(name)-l > 63:
		return fmt.Errorf("cookie domain: byte length of top level domain '%s' is %d, can't exceed 63", name[l:], len(name)-l)
	case name[l] == '-':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d begins with a hyphen", name[l:], l)
	case name[len(name)-1] == '-':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d ends with a hyphen", name[l:], l)
	case name[l] >= '0' && name[l] <= '9':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d begins with a digit", name[l:], l)
	}
	return nil
}

func throttle(limit int) gin.HandlerFunc {
	store := memory.NewStore()
	// Create a new middleware with the limiter instance.
	return middlewareGin.NewMiddleware(limiter.New(store, limiter.Rate{
		Period: time.Minute,
		Limit:  int64(limit),
	}))
}

func auth(c *gin.Context) {
	if c.Request.Header.Get("X-API-KEY") != os.Getenv("API_KEY") {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		c.Abort()
	}
	c.Next()
}
