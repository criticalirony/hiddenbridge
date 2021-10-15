package gitcache

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hiddenbridge/pkg/utils"
	"net/http"
	"net/url"
	"sync"

	"github.com/rs/zerolog/log"
)

type contextKey int

type GitService struct {
	Path    string
	Method  string
	Handler func(w http.ResponseWriter, r *http.Request)
}

type GitRequestContext struct {
	repoRoot string
	upstream *url.URL
	status   int
	err      error
}

type GitRepoContext struct {
	hash string
	task *utils.Task
}

const (
	gitCacheKey contextKey = iota
)

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

	repoContexts sync.Map
)

func init() {
	repoContexts = sync.Map{}
}

func getRepoContext(host, path string) *GitRepoContext {
	contextKey := host + path

	var (
		repoContext *GitRepoContext
	)

	rawContext, ok := repoContexts.Load(contextKey)
	if ok {
		repoContext = rawContext.(*GitRepoContext)
		log.Debug().Msgf("using cached repo context: %s", contextKey)
	} else {
		rawHash := sha1.Sum([]byte(contextKey))

		repoContext = &GitRepoContext{
			hash: hex.EncodeToString(rawHash[:]),
			task: utils.NewTask("", nil),
		}

		log.Debug().Msgf("using generated repo key: %s", contextKey)
		repoContexts.Store(contextKey, repoContext)
	}

	return repoContext
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
	var (
		ok             bool
		requestContext *GitRequestContext
	)
	// gitcache.org:80/golang/dl.git/info/refs?service=git-upload-pack (client fetch/clone)
	// gitcache.org:80/golang/dl.git/info/refs?service=git-receive-pack (client push)

	if requestContext, ok = r.Context().Value(gitCacheKey).(*GitRequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", r.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", r.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	log.Debug().Msgf("repo root: %s", requestContext.repoRoot)

	repoContext := getRepoContext(r.Host, r.URL.Path)
	_ = repoContext

	// repoContext := getRepoContext(r.Host, r.URL.Path)
	// repoRoot, ok := r.Context().Value(gitCacheKey).(*GitRepoContext)
	// if !ok {
	// 	log.Warn().Msgf("request context does not contain git repo data")
	// }

	// _ = repoRoot

	// log.Debug().Msgf("repo root: %s", repoRoot)

	// basePath := mux.Vars(r)["path"]
	// repoHash := getRepoContext(r.Host, basePath)
	// _ = repoHash

	// hdrsNoCache(w)

	// serviceName := r.URL.Query().Get("service")
	// if serviceName != "" {
	// 	// Do something here
	// } else {
	// 	// Send file as plain data
	// }

	requestContext.status = http.StatusNotFound
	if w != nil {
		http.NotFound(w, r)
	}
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
