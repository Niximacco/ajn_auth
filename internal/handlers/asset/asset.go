// Package asset_handler serves the files that every page links to.
package asset_handler

import (
	"github.com/Niximacco/ajn_auth/internal/web"
	"github.com/gin-gonic/gin"
)

// AddAssetV1 mounts the embedded stylesheet.
//
// There is no session on this route on purpose. The css is the same file for
// everybody, the confirm page needs it before anybody is signed in to anything,
// and the name it is served under is a hash of its own contents, so the route
// cannot be asked for anything that is not already compiled into this binary.
func AddAssetV1(router *gin.Engine) {
	router.GET("/static/:file", web.ServeAsset)
}
