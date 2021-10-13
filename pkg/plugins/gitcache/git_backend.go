package gitcache

import (
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

type contextKey int

const (
	gitRepoRootKey contextKey = iota
)

type GitService struct {
	Path    string
	Method  string
	Handler func(w http.ResponseWriter, r *http.Request)
}

var (
	gitServices = []GitService{
		{`/HEAD`, http.MethodGet, getHead},
		{`/info/refs`, http.MethodGet, getInfoRefs},
		{`/objects/info/alternates`, http.MethodGet, getTextFile},
		{`/objects/info/http-alternates`, http.MethodGet, getTextFile},
		{`/objects/info/packs`, http.MethodGet, getInfoPacks},
		{`/objects/[0-9a-f]{2}/[0-9a-f]{38}`, http.MethodGet, getLooseObject},
		{`/objects/[0-9a-f]{2}/[0-9a-f]{62}`, http.MethodGet, getLooseObject},
		{`/objects/pack/pack-[0-9a-f]{40}\.pack`, http.MethodGet, getPackFile},
		{`/objects/pack/pack-[0-9a-f]{64}\.pack`, http.MethodGet, getPackFile},
		{`/objects/pack/pack-[0-9a-f]{40}\.idx`, http.MethodGet, getIdxFile},
		{`/objects/pack/pack-[0-9a-f]{64}\.idx`, http.MethodGet, getIdxFile},
		{`/git-upload-pack`, http.MethodPost, serviceRPC},
		{`/git-receive-pack`, http.MethodPost, serviceRPC},
	}

	repoContext sync.Map
)

func init() {
	repoContext = sync.Map{}
}

func getRepoHash(host, path string) string {
	repoKey := host + path

	var (
		repoHash string
	)

	rawHash, ok := repoContext.Load(repoKey)
	if ok {
		repoHash = rawHash.(string)
		log.Debug().Msgf("using cached repo key: %s", repoHash)
	} else {
		rawHash := sha1.Sum([]byte(repoKey))
		repoHash = hex.EncodeToString(rawHash[:])
		log.Debug().Msgf("using generated repo key: %s", repoHash)
		repoContext.Store(repoKey, repoHash)
	}

	return repoHash
}

func hdrsNoCache(w http.ResponseWriter) {
	w.Header().Add("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	w.Header().Add("Pragma", "no-cache")
	w.Header().Add("Cache-Control", "no-cache, max-age=0, must-revalidate")
}

func getHead(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func getInfoRefs(w http.ResponseWriter, r *http.Request) {
	// gitcache.org:80/golang/dl.git/info/refs?service=git-upload-pack (client fetch/clone)
	// gitcache.org:80/golang/dl.git/info/refs?service=git-receive-pack (client push)

	repoRoot := r.Context().Value(gitRepoRootKey).(string)
	log.Debug().Msgf("repo root: %s", repoRoot)

	basePath := mux.Vars(r)["path"]
	repoHash := getRepoHash(r.Host, basePath)
	_ = repoHash

	hdrsNoCache(w)

	serviceName := r.URL.Query().Get("service")
	if serviceName != "" {
		// Do something here
	} else {
		// Send file as plain data
	}

	http.NotFound(w, r)
}

func getTextFile(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func getInfoPacks(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func getLooseObject(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func getPackFile(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func getIdxFile(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func serviceRPC(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
