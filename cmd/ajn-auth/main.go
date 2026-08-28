package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	data "github.com/Niximacco/ajn_auth/internal/cloud"
	"github.com/Niximacco/ajn_auth/internal/config"
	admin_handler "github.com/Niximacco/ajn_auth/internal/handlers/admin"
	api_handler "github.com/Niximacco/ajn_auth/internal/handlers/api"
	asset_handler "github.com/Niximacco/ajn_auth/internal/handlers/asset"
	callback_handler "github.com/Niximacco/ajn_auth/internal/handlers/callback"
	"github.com/Niximacco/ajn_auth/internal/router"
	"github.com/Niximacco/ajn_auth/internal/sites"
	"github.com/gin-gonic/gin"
)

var PORT = ""

func init() {
	PORT = os.Getenv("PORT")
	if PORT == "" {
		PORT = "8080"
	}

	data.Initialize()

	// The roster is read here rather than lazily, so a service that cannot see
	// its own configuration fails at start where a deploy will show it, rather
	// than at somebody's first login.
	sites.Initialize(config.SITES_SECRET)
}

func main() {
	if os.Getenv("mode") != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := router.New()

	// Cloud Run needs something to probe that does not require a session.
	router.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// The front page of a service nobody is meant to visit directly. A person
	// who lands here typed the domain or followed a stale bookmark; the sites
	// are where logins start.
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/admin")
	})

	asset_handler.AddAssetV1(router)
	api_handler.AddAPIV1(router)
	callback_handler.AddCallbackV1(router)
	admin_handler.AddAdminV1(router)

	log.Printf("Running %s on :%s...", config.SERVICE_NAME, PORT)
	if err := router.Run(fmt.Sprintf(":%s", PORT)); err != nil {
		log.Fatal(err.Error())
	}
}
