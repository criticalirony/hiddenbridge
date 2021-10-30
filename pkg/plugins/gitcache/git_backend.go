package gitcache

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hiddenbridge/pkg/server/request"
	"hiddenbridge/pkg/utils"
	"hiddenbridge/pkg/utils/git"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

var (
	ErrBadContext = errors.New("bad context")
)

type GitService struct {
	Path    string
	Method  string
	Handler func(w http.ResponseWriter, r *http.Request)
}

type GitRepoContext struct {
	key         string
	hash        string
	lock        *utils.Lock
	lastUpdated time.Time
	ext         map[string]interface{}
}

var (
	gitServices = []GitService{
		{`/HEAD`, http.MethodGet, getTextFile},
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

func getRepoContext(u *url.URL) *GitRepoContext {
	contextKey := u.Hostname() + "/" + strings.TrimSuffix(u.Path, ".git")

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
			key:  contextKey,
			hash: hex.EncodeToString(rawHash[:]),
			lock: &utils.Lock{},
			ext:  map[string]interface{}{},
		}

		log.Debug().Msgf("using generated repo key: %s: %s", contextKey, repoContext.hash)
		repoContexts.Store(contextKey, repoContext)
	}

	return repoContext
}

func hdrsNoCache(w http.ResponseWriter) {
	w.Header().Add("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	w.Header().Add("Pragma", "no-cache")
	w.Header().Add("Cache-Control", "no-cache, max-age=0, must-revalidate")
}

func sendFile(filePath string, fi os.FileInfo, content_type string, w http.ResponseWriter, req *http.Request) {
	var (
		err error
	)

	if fi == nil {
		if fi, err = os.Stat(filePath); os.IsNotExist(err) {
			http.NotFound(w, req)
			return
		}
	}

	w.Header().Set("Content-Type", content_type)
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.Header().Set("Last-Modified", fi.ModTime().Format(http.TimeFormat))
	http.ServeFile(w, req, filePath)
}

func repoExists(gitDir string, reqCtx request.RequestContext, repoCtx *GitRepoContext) (bool, error) {
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return false, nil
	} else {
		f, err := os.Open(gitDir)
		if err != nil {
			return false, xerrors.Errorf("failed to open repo dir: %w", err)
		}
		defer f.Close()

		dirs, err := f.Readdirnames(-1)
		if err != nil && !errors.Is(err, io.EOF) {
			return false, xerrors.Errorf("failed to read repo dir: %w", err)
		}
		f.Close() // Duplicating close, but better to have it closed sooner than later

		if len(dirs) == 0 {
			return false, nil
		}
	}

	// Validate that the existing repo has a valid remote
	if _, err := git.ResolveGitDir(gitDir, 60*time.Second); err != nil {
		return false, xerrors.Errorf("resolve git dir failure: %w", err)
	}

	return true, nil
}

func loadRequestMetadata(req *http.Request) (request.RequestContext, *GitRepoContext, string, error) {
	var (
		ok      bool
		reqCtx  request.RequestContext
		repoCtx *GitRepoContext
	)

	if reqCtx, ok = req.Context().Value(request.ReqContextKey).(request.RequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		return nil, nil, "", xerrors.Errorf("unable to retrieve git cache context for this request: %s: %w", req.URL.String(), ErrBadContext)
	}

	repoPath, ok := mux.Vars(req)["path"]
	if !ok {
		return nil, nil, "", xerrors.Errorf("info/refs request failure: repo path is not available: %w", utils.ErrHTTPNotFound)
	}

	repoCtx = getRepoContext(&url.URL{
		Host: req.Host,
		Path: repoPath,
	})

	return reqCtx, repoCtx, repoPath, nil
}

func getInfoRefsReq(req *http.Request, reqCtx request.RequestContext, repoCtx *GitRepoContext, repoPath string) error {
	// // gitcache.org:80/golang/dl.git/info/refs?service=git-upload-pack (client fetch/clone)
	// // gitcache.org:80/golang/dl.git/info/refs?service=git-receive-pack (client push)

	var repoRoot string
	utils.As(reqCtx["reporoot"], &repoRoot)
	gitDir := filepath.Join(repoRoot, repoCtx.hash)

	hasRepo, err := repoExists(gitDir, reqCtx, repoCtx)
	if err != nil {
		return err
	}

	var upstreamURL *url.URL
	utils.As(reqCtx["upstream"], &upstreamURL)

	var gitProxy string
	utils.As(reqCtx["gitproxy"], &gitProxy)

	// Attempting to lock the repo here is easiet way to check if we currently have
	// pending operations already running.
	// If acquired this lock will release and allow any pending tasks to start
	if repoCtx.lock.TryAcquire() {
		defer repoCtx.lock.Release()
	} else {
		log.Warn().Msgf("failure to acquire lock for repo: %s", gitDir)
		return nil
	}

	if time.Since(repoCtx.lastUpdated) < 5*time.Minute {
		log.Warn().Msgf("failed to update repo: %s for cache: lastupdated: %s", gitDir, time.Since(repoCtx.lastUpdated))
		return nil // It hasn't been long enough since last repo update
	}

	if !hasRepo {

		// The cached copy of the repo does not yet exist, create it.
		if err := os.MkdirAll(gitDir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to create repo dir: %w", err)
		}

		if !utils.URLIsEmpty(upstreamURL) {
			// Repo doesn't exist locally yet.. attempt to clone from the upstream
			cloneURL := &url.URL{}
			*cloneURL = *upstreamURL // Shallow copy
			cloneURL.Path = repoPath
			cloneURL.RawQuery = ""

			task := utils.NewTask("", func(ctx interface{}) error {
				if err := repoCtx.lock.AcquireWithTimeout(3600 * time.Second); err != nil {
					return xerrors.Errorf("task: obtain repo lock failure: %w", err)
				}
				defer repoCtx.lock.Release()

				repoCtx.lastUpdated = time.Now()

				if err := git.Clone(cloneURL.String(), gitDir, true, true, gitProxy, 3600*time.Second); err != nil {
					return xerrors.Errorf("task: run failure: %w", err)
				}

				if _, err := git.Run("", gitDir, 60*time.Second, "update-server-info"); err != nil {
					return xerrors.Errorf("task: git update-server-info failure: %w", err)
				}

				ioutil.WriteFile(filepath.Join(gitDir, "repoinfo.txt"), []byte(fmt.Sprintf("{\"key\": \"%s\"}\n", repoCtx.key)), os.ModePerm)

				repoCtx.lastUpdated = time.Now()
				return nil
			}, nil)

			if err := task.Run(nil); err != nil {
				return xerrors.Errorf("failed to clone repo: %s: %w", cloneURL.String(), err)
			}
		} else {
			// We need to create a new repo, but don't have an upstream remote to clone from
			if err := git.Init(gitDir, true, 10*time.Second); err != nil {
				return xerrors.Errorf("failed to init repo: %s: %w", gitDir, err)
			}

			if _, err := git.Run("", gitDir, 60*time.Second, "update-server-info"); err != nil {
				return xerrors.Errorf("task: git update-server-info failure: %w", err)
			}

			ioutil.WriteFile(filepath.Join(gitDir, "repoinfo.txt"), []byte(fmt.Sprintf("{\"key\": \"%s\"}", repoCtx.key)), os.ModePerm)

			repoCtx.lastUpdated = time.Now()
		}
	} else if hasRepo && !utils.URLIsEmpty(upstreamURL) {
		// we have an existing repo dir and an upstream.. so just task an update
		task := utils.NewTask("", func(ctx interface{}) error {
			if err := repoCtx.lock.AcquireWithTimeout(3600 * time.Second); err != nil {
				return xerrors.Errorf("task: obtain repo lock failure: %w", err)
			}
			defer repoCtx.lock.Release()

			repoCtx.lastUpdated = time.Now()
			if _, err := git.Remote("update", true, gitDir, gitProxy, 3600*time.Second); err != nil {
				return xerrors.Errorf("task: git remote update failure: %w", err)
			}

			if _, err := git.Run("", gitDir, 60*time.Second, "update-server-info"); err != nil {
				return xerrors.Errorf("task: git update-server-info failure: %w", err)
			}
			repoCtx.lastUpdated = time.Now()
			return nil
		}, nil)

		if err := task.Run(nil); err != nil {
			return xerrors.Errorf("failed to update repo: %s: %w", gitDir, err)
		}
	}
	return nil
}

func getInfoRefsResp(w http.ResponseWriter, req *http.Request, reqCtx request.RequestContext, repoCtx *GitRepoContext, repoPath string) error {

	if !strings.HasPrefix(repoPath, "/") {
		repoPath = "/" + repoPath
	}

	var repoRoot string
	utils.As(reqCtx["reporoot"], &repoRoot)
	refsFile := filepath.Join(repoRoot, repoCtx.hash, strings.TrimPrefix(req.URL.Path, repoPath))

	var upstreamURL *url.URL
	if !utils.As(reqCtx["upstream"], &upstreamURL) || upstreamURL == nil {
		if _, err := os.Stat(refsFile); os.IsNotExist(err) {
			log.Warn().Err(err).Msgf("local cache refs file: %s not found", refsFile)
			http.NotFound(w, req)
			return nil
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		refsData, err := ioutil.ReadFile(refsFile)
		if err != nil {
			return xerrors.Errorf("local cache refs file: %s read failure: %w", refsFile, err)
		}

		w.WriteHeader(http.StatusOK)
		w.Write(refsData)
	}

	return nil
}

func getInfoRefs(w http.ResponseWriter, req *http.Request) {
	reqCtx, repoCtx, repoPath, err := loadRequestMetadata(req)
	if err != nil {
		reqCtx["err"] = err
		return
	}

	if w == nil {
		// This is a request handler
		reqCtx["err"] = getInfoRefsReq(req, reqCtx, repoCtx, repoPath)
	} else {
		// This is the response handler
		reqCtx["err"] = getInfoRefsResp(w, req, reqCtx, repoCtx, repoPath)
	}
}

func getTextFileReq(req *http.Request, reqCtx request.RequestContext, repoCtx *GitRepoContext, repoPath string) error {
	if !strings.HasPrefix(repoPath, "/") {
		repoPath = "/" + repoPath
	}

	var repoRoot string
	utils.As(reqCtx["reporoot"], &repoRoot)
	textFile := filepath.Join(repoRoot, repoCtx.hash, strings.TrimPrefix(req.URL.Path, repoPath))

	if _, err := os.Stat(textFile); os.IsExist(err) {
		// This file can be served by the cache, no need to send the request upstream
		reqCtx["upstream"] = nil
	}

	return nil
}

func getTextFileResp(w http.ResponseWriter, req *http.Request, reqCtx request.RequestContext, repoCtx *GitRepoContext, repoPath string) error {
	var (
		err      error
		repoRoot string
		fi       os.FileInfo
	)

	if !strings.HasPrefix(repoPath, "/") {
		repoPath = "/" + repoPath
	}

	utils.As(reqCtx["reporoot"], &repoRoot)
	textFile := filepath.Join(repoRoot, repoCtx.hash, strings.TrimPrefix(req.URL.Path, repoPath))

	if fi, err = os.Stat(textFile); os.IsNotExist(err) {
		// This file can't be served by the cache, either serve the upstream result or issue 404 not found
		var upstream *url.URL
		if utils.As(reqCtx["upstream"], upstream) && upstream != nil {
			return nil
		}

		http.NotFound(w, req)
	}

	hdrsNoCache(w)
	sendFile(textFile, fi, "text/plain", w, req)
	return nil
}

func getTextFile(w http.ResponseWriter, req *http.Request) {
	reqCtx, repoCtx, repoPath, err := loadRequestMetadata(req)
	if err != nil {
		reqCtx["err"] = err
		return
	}

	if w == nil {
		// This is a request handler
		reqCtx["err"] = getTextFileReq(req, reqCtx, repoCtx, repoPath)
	} else {
		// This is the response handler
		reqCtx["err"] = getTextFileResp(w, req, reqCtx, repoCtx, repoPath)
	}
}

func getInfoPacks(w http.ResponseWriter, req *http.Request) {
	var (
		ok     bool
		reqCtx request.RequestContext
	)

	if reqCtx, ok = req.Context().Value(request.ReqContextKey).(request.RequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = reqCtx
}

func getLooseObject(w http.ResponseWriter, req *http.Request) {
	var (
		ok     bool
		reqCtx request.RequestContext
	)

	if reqCtx, ok = req.Context().Value(request.ReqContextKey).(request.RequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = reqCtx
}

func getPackFile(w http.ResponseWriter, req *http.Request) {
	var (
		ok     bool
		reqCtx request.RequestContext
	)

	if reqCtx, ok = req.Context().Value(request.ReqContextKey).(request.RequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = reqCtx
}

func getIdxFile(w http.ResponseWriter, req *http.Request) {
	var (
		ok     bool
		reqCtx request.RequestContext
	)

	if reqCtx, ok = req.Context().Value(request.ReqContextKey).(request.RequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = reqCtx
}

func serviceRPC(w http.ResponseWriter, req *http.Request) {
	var (
		ok     bool
		reqCtx request.RequestContext
	)

	if reqCtx, ok = req.Context().Value(request.ReqContextKey).(request.RequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = reqCtx
}
