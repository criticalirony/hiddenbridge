package gitcache

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hiddenbridge/pkg/utils"
	"hiddenbridge/pkg/utils/git"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type contextKey int

type GitService struct {
	Path    string
	Method  string
	Handler func(w http.ResponseWriter, r *http.Request)
}

type GitRequestContext struct {
	repoRoot   string
	gitProxy   string
	upstream   *url.URL
	body       io.Reader
	statusCode int
	err        error
}

type GitRepoContext struct {
	hash string
	task *utils.Task
}

const (
	reqContextKey contextKey = iota
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
			hash: hex.EncodeToString(rawHash[:]),
			task: utils.NewTask("", nil),
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

func repoExists(gitDir string, reqCtx *GitRequestContext, repoCtx *GitRepoContext) (bool, error) {
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

func getHeadReq(req *http.Request) {

}

func getHeadResp(w http.ResponseWriter, req *http.Request) {

}

func getHead(w http.ResponseWriter, req *http.Request) {
	if w == nil {
		// This is a request handler
		getHeadReq(req)
	} else {
		getHeadResp(w, req)
	}
}

func getInfoRefsReq(req *http.Request, reqCtx *GitRequestContext, repoCtx *GitRepoContext, repoPath string) error {
	// // gitcache.org:80/golang/dl.git/info/refs?service=git-upload-pack (client fetch/clone)
	// // gitcache.org:80/golang/dl.git/info/refs?service=git-receive-pack (client push)

	gitDir := filepath.Join(reqCtx.repoRoot, repoCtx.hash)

	hasRepo, err := repoExists(gitDir, reqCtx, repoCtx)
	if err != nil {
		return err
	}

	if !hasRepo {
		if err := os.MkdirAll(gitDir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to create repo dir: %w", err)
		}

		// Clone
		if !utils.URLIsEmpty(reqCtx.upstream) {
			// Repo doesn't exist locally yet.. attempt clone from upstream
			cloneURL := *reqCtx.upstream
			cloneURL.Path = repoPath
			cloneURL.RawQuery = ""

			repoCtx.task.SetFunction(func(ctx interface{}) error {
				if err := git.Clone(cloneURL.String(), gitDir, true, true, reqCtx.gitProxy, 3600*time.Second); err != nil {
					return xerrors.Errorf("task: run failure: %w", err)
				}

				if _, err := git.Run("", gitDir, 60*time.Second, "update-server-info"); err != nil {
					return xerrors.Errorf("task: git update-server-info failure: %w", err)
				}

				return nil
			})

			if err := repoCtx.task.RunIfOlder(nil, 5*time.Minute); err != nil {
				var errExpiry utils.ErrExpiry

				if errors.As(err, &errExpiry) {
					log.Warn().Err(errExpiry).Msg("task run failure: task has not expired")
				} else if !errors.Is(err, utils.ErrLockBusy) {
					return xerrors.Errorf("failed to clone repo: %s: %w", cloneURL.String(), err)
				}
			}
		} else {
			if err := git.Init(gitDir, true, 10*time.Second); err != nil {
				return xerrors.Errorf("failed to init repo: %s: %w", gitDir, err)
			}

			if _, err := git.Run("", gitDir, 60*time.Second, "update-server-info"); err != nil {
				return xerrors.Errorf("task: git update-server-info failure: %w", err)
			}
		}
	} else if hasRepo && !utils.URLIsEmpty(reqCtx.upstream) {
		// we have an existing repo dir and an upstream.. so just task an update
		repoCtx.task.SetFunction(func(ctx interface{}) error {
			if _, err := git.Remote("update", true, gitDir, reqCtx.gitProxy, 3600*time.Second); err != nil {
				return xerrors.Errorf("task: git remote update failure: %w", err)
			}

			if _, err := git.Run("", gitDir, 60*time.Second, "update-server-info"); err != nil {
				return xerrors.Errorf("task: git update-server-info failure: %w", err)
			}

			return nil
		})

		if err := repoCtx.task.RunIfOlder(nil, 5*time.Minute); err != nil {
			var errExpiry utils.ErrExpiry

			if errors.As(err, &errExpiry) {
				log.Warn().Err(errExpiry).Msg("task run failure: task has not expired")
			} else if !errors.Is(err, utils.ErrLockBusy) {
				return xerrors.Errorf("failed to update repo: %s: %w", gitDir, err)
			}
		}
	}

	return nil
}

func getInfoRefsResp(w http.ResponseWriter, req *http.Request, reqCtx *GitRequestContext, repoCtx *GitRepoContext, repoPath string) error {

	// Refs are returned by upstream if available
	if !utils.URLIsEmpty(reqCtx.upstream) {
		return nil
	}

	if !strings.HasPrefix(repoPath, "/") {
		repoPath = "/" + repoPath
	}

	refsFile := filepath.Join(reqCtx.repoRoot, repoCtx.hash, strings.TrimPrefix(req.URL.Path, repoPath))

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

	w.Write(refsData)

	return nil
}

func getInfoRefs(w http.ResponseWriter, req *http.Request) {
	var (
		ok      bool
		reqCtx  *GitRequestContext
		repoCtx *GitRepoContext
	)

	if reqCtx, ok = req.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		return
	}

	repoPath, ok := mux.Vars(req)["path"]
	if !ok {
		reqCtx.err = xerrors.Errorf("info/refs request failure: repo path is not available: %w", utils.ErrHTTPNotFound)
		return
	}

	if !utils.URLIsEmpty(reqCtx.upstream) {
		repoCtx = getRepoContext(&url.URL{
			Host: reqCtx.upstream.Host,
			Path: repoPath,
		})
	} else {
		repoCtx = getRepoContext(&url.URL{
			Host: req.Host,
			Path: repoPath,
		})
	}

	if w == nil {
		// This is a request handler
		reqCtx.err = getInfoRefsReq(req, reqCtx, repoCtx, repoPath)
	} else {
		// This is the response handler
		reqCtx.err = getInfoRefsResp(w, req, reqCtx, repoCtx, repoPath)
	}
}

func getTextFile(w http.ResponseWriter, req *http.Request) {
	var (
		ok             bool
		requestContext *GitRequestContext
	)

	if requestContext, ok = req.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = requestContext
}

func getInfoPacks(w http.ResponseWriter, req *http.Request) {
	var (
		ok             bool
		requestContext *GitRequestContext
	)

	if requestContext, ok = req.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = requestContext
}

func getLooseObject(w http.ResponseWriter, req *http.Request) {
	var (
		ok             bool
		requestContext *GitRequestContext
	)

	if requestContext, ok = req.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = requestContext
}

func getPackFile(w http.ResponseWriter, req *http.Request) {
	var (
		ok             bool
		requestContext *GitRequestContext
	)

	if requestContext, ok = req.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = requestContext
}

func getIdxFile(w http.ResponseWriter, req *http.Request) {
	var (
		ok             bool
		requestContext *GitRequestContext
	)

	if requestContext, ok = req.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = requestContext
}

func serviceRPC(w http.ResponseWriter, req *http.Request) {
	var (
		ok             bool
		requestContext *GitRequestContext
	)

	if requestContext, ok = req.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Error().Msgf("unable to retrieve git cache context for this request: %s", req.URL.String())
		if w != nil {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
		}
		return
	}

	_ = requestContext
}
