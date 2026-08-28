package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

// The stylesheet ships inside the binary alongside the templates, for the same
// reason they do: a deploy stays one container with nothing to sync anywhere.
//
// It is served as a file rather than written into every page because a browser
// that already has it should not be sent it again. The pages themselves cannot
// be cached - they are per-account and per-session - so the css is the one part
// of a page load worth making free on the second visit.
//
//go:embed static/*
var assetFS embed.FS

// Asset is one served file, addressed by a name that contains a hash of what is
// in it. Change the file and the name changes with it, which is what makes it
// safe to tell a browser to keep the old one forever: nothing ever asks for
// that name again.
type Asset struct {
	// Path is the url the pages link to, "/static/app.a1b2c3d4e5.css".
	Path string
	// ETag is the same hash, quoted, for a browser that asks whether what it
	// already has is still current.
	ETag        string
	ContentType string
	Body        []byte
}

// assets is every embedded file, keyed by the hashed name it is served under.
var assets = map[string]Asset{}

// Stylesheet is the versioned path of the service's css, handed to every page.
var Stylesheet = ""

func init() {
	entries, err := fs.ReadDir(assetFS, "static")
	if err != nil {
		log.Fatalf("could not read the embedded assets: %s", err.Error())
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		body, err := assetFS.ReadFile("static/" + entry.Name())
		if err != nil {
			log.Fatalf("could not read the embedded asset %s: %s", entry.Name(), err.Error())
		}

		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])[:10]

		extension := path.Ext(entry.Name())
		name := strings.TrimSuffix(entry.Name(), extension) + "." + digest + extension

		contentType := mime.TypeByExtension(extension)
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		assets[name] = Asset{
			Path:        "/static/" + name,
			ETag:        `"` + digest + `"`,
			ContentType: contentType,
			Body:        body,
		}

		if entry.Name() == "app.css" {
			Stylesheet = "/static/" + name
		}
	}

	if Stylesheet == "" {
		log.Fatal("the embedded assets do not include app.css")
	}
}

// ServeAsset hands back one of the embedded files. It is deliberately outside
// the session: a stylesheet is the same for everybody, and the confirm page
// needs it before anybody is signed in to anything.
func ServeAsset(c *gin.Context) {
	asset, ok := assets[c.Param("file")]
	if !ok {
		// AbortWithStatus rather than Status: gin holds a status back until
		// something writes a body, and these two answers have no body to write.
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	// The name contains the hash of the contents, so this exact url can never
	// answer with anything else. That is what "immutable" is promising, and it
	// is the whole reason for the hash being in the name.
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.Header("ETag", asset.ETag)

	// A browser coming back after a deploy that did not touch the css still
	// asks once. Answering that with an empty 304 rather than the file is most
	// of the benefit for none of the bytes.
	if match := c.GetHeader("If-None-Match"); match != "" && strings.Contains(match, asset.ETag) {
		c.AbortWithStatus(http.StatusNotModified)
		return
	}

	c.Data(http.StatusOK, asset.ContentType, asset.Body)
}
