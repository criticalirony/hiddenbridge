package gitcache

import (
	"context"
	"errors"
	"fmt"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/utils"
	"hiddenbridge/pkg/utils/command"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

var (
	pluginName = utils.PackageAsName()
	self       plugins.Plugin
	selfgch    *GitCacheHandler

	host      = "testhost.org"
	cachePath = "/tmp/gitcache/test"

	opts = &options.OptionValue{}
)

func init() {
	SetupLogging("debug")

	self = plugins.PluginBuilder[pluginName]()
	selfgch = self.(*GitCacheHandler)

	opts.Set("hosts", []string{host})
	opts.Set("cache.path", cachePath)

	if err := os.RemoveAll(cachePath); err != nil {
		log.Panic().Msgf("faillure to remove: %s", cachePath)
	}

	if err := self.Init(opts); err != nil {
		log.Panic().Msgf("init failure: %+v", err)
	}

	selfgch := self.(*GitCacheHandler)
	selfgch.r.HandleFunc(`/{path:.*?}/test`, testRoute)
	selfgch.r.HandleFunc("/{path:.*?}", testRoute)
}

func testRoute(w http.ResponseWriter, r *http.Request) {
	var (
		err            error
		ok             bool
		requestContext *GitRequestContext
	)

	urlQuery := r.URL.Query()
	isServedLocal := urlQuery.Get("served")        // Is this route served locally
	isLaunchingTask := urlQuery.Get("task")        // Should this route launch an async task
	checkLastUpdatedRaw := urlQuery.Get("updated") // Should we consider when the repo was last updated before running a new task

	if requestContext, ok = r.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Panic().Msgf("unable to retrieve git cache context for this request: %s", r.URL.String())
	}

	if isServedLocal == "true" {
		requestContext.upstream = nil
	}

	if isLaunchingTask == "true" {
		testRoot := requestContext.repoRoot
		testPath, ok := mux.Vars(r)["path"]
		if !ok {
			log.Panic().Msgf("launch task failure: no path provided")
		}

		repoContext := getRepoContext(&url.URL{
			Host: r.Host,
			Path: testPath,
		})

		if repoContext == nil {
			log.Panic().Msgf("launch task failure: repo context not available")
		}

		var checkLastUpdated time.Duration
		if checkLastUpdatedRaw != "" {
			checkLastUpdated, err = time.ParseDuration(checkLastUpdatedRaw)
			if err != nil {
				log.Panic().Err(err).Msgf("launch task failure: check since updated: %s cannot be parsed", checkLastUpdatedRaw)
			}
		}

		if time.Since(repoContext.lastUpdated) < checkLastUpdated {
			repoContext.ext["err"] = utils.ErrTaskNotExpired
			return
		}

		task := utils.NewTask("", func(ctx interface{}) error {
			repoContext.lastUpdated = time.Now()
			cmdCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := command.Run(cmdCtx, "", nil, "/bin/bash", "-c", fmt.Sprintf("sleep 2; echo \"I am a successful test result\" >> %s", filepath.Join(testRoot, repoContext.hash, "test.txt")))
			if err != nil {
				log.Panic().Err(err).Msgf("command run test failure")
			}
			repoContext.lastUpdated = time.Now()
			return nil
		}, nil)

		if err := task.Run(nil); err != nil {
			log.Warn().Err(err).Msg("command run test failure")
		}

		repoContext.ext["task"] = task
	}
}

func SetupLogging(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Panic().Err(err).Msgf("Failed to parse log level: %s", level)
	}

	noColor := !utils.IsTerminal()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: noColor}).Level(logLevel).With().Timestamp().Logger().With().Caller().Logger()
}

func TestGitCacheSimple(t *testing.T) {
	var (
		err  error
		req  *http.Request
		resp *httptest.ResponseRecorder
	)

	input := "this is a refs file\n"

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/sample/project.git/info/refs?service=git-upload-pack", host), nil)
	resp = httptest.NewRecorder()

	_, req, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.NotNil(t, req)

	repoPath, ok := mux.Vars(req)["path"]
	require.True(t, ok)

	repoCtx := getRepoContext(&url.URL{
		Host: req.Host,
		Path: repoPath,
	})

	localRepoDir := filepath.Join(selfgch.cachePath, repoCtx.hash)
	if !strings.HasPrefix(repoPath, "/") {
		repoPath = "/" + repoPath
	}
	localFilePath := strings.TrimPrefix(req.URL.Path, repoPath)

	os.MkdirAll(filepath.Join(localRepoDir, filepath.Dir(localFilePath)), os.ModePerm)
	os.WriteFile(filepath.Join(localRepoDir, localFilePath), []byte(input), os.ModePerm)
	defer os.RemoveAll(localRepoDir) // Best effort

	err = self.HandleResponse(resp, req, nil, http.StatusOK)
	require.Nil(t, err)

	res := resp.Result()
	require.Equal(t, http.StatusOK, res.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, input, string(body))

}

func TestGitCacheMethodHead(t *testing.T) {
	var (
		err  error
		req  *http.Request
		resp *httptest.ResponseRecorder
	)

	input := "this is a refs file\n"

	// Requesting HEAD
	req = httptest.NewRequest(http.MethodHead, fmt.Sprintf("http://%s/sample/project.git/info/refs?service=git-upload-pack", host), nil)
	resp = httptest.NewRecorder()

	_, req, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.NotNil(t, req)

	repoPath, ok := mux.Vars(req)["path"]
	require.True(t, ok)

	repoCtx := getRepoContext(&url.URL{
		Host: req.Host,
		Path: repoPath,
	})

	localRepoDir := filepath.Join(selfgch.cachePath, repoCtx.hash)
	if !strings.HasPrefix(repoPath, "/") {
		repoPath = "/" + repoPath
	}
	localFilePath := strings.TrimPrefix(req.URL.Path, repoPath)

	os.MkdirAll(filepath.Join(localRepoDir, filepath.Dir(localFilePath)), os.ModePerm)
	os.WriteFile(filepath.Join(localRepoDir, localFilePath), []byte(input), os.ModePerm)
	defer os.RemoveAll(localRepoDir) // Best effort

	err = self.HandleResponse(resp, req, nil, http.StatusOK)
	require.Nil(t, err)

	res := resp.Result()

	// Checking method has been updated to GET
	require.Equal(t, http.MethodGet, req.Method)
	require.NotEqual(t, http.StatusNotFound, res.StatusCode)
}

func TestGitCacheHandleRequest(t *testing.T) {
	var (
		err       error
		ok        bool
		req       *http.Request
		resultURL *url.URL
		resultReq *http.Request

		requestContext *GitRequestContext
	)

	// Test cases
	// 1. No local route, no upstream
	// 2. No local route, upstream
	// 3. Local route, served, no upstream
	// 4. Local route, served, upstream
	// 5. Local route, not served, no upstream
	// 6. Local route, not served, upstream

	upstreamPath := "https://upstream.org:443/project.git/info/refs?service=git-upload-pack"
	upstreamURL, err := utils.NormalizeURL(upstreamPath)
	require.Nil(t, err)

	// Test 1.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/local/path/not/found", host), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Nil(t, requestContext.upstream)

	// Test 2.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/local/path/not/found", host), nil)
	req.Header.Add(HB_GIT_UPSTREAM_HEADER_FIELD, upstreamPath)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Equal(t, upstreamURL.String(), resultURL.String())
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, upstreamURL.String(), requestContext.upstream.String())

	// Test 3.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test?served=true", host), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Nil(t, requestContext.upstream)

	// Test 4.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test?served=true", host), nil)
	req.Header.Add(HB_GIT_UPSTREAM_HEADER_FIELD, upstreamPath)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Nil(t, requestContext.upstream)

	// Test 5.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test?served=false", host), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Nil(t, requestContext.upstream)

	// Test 6.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test?served=false", host), nil)
	req.Header.Add(HB_GIT_UPSTREAM_HEADER_FIELD, upstreamPath)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Equal(t, upstreamPath, resultURL.String())
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, upstreamPath, requestContext.upstream.String())
}

func TestGitCacheLaunchTask(t *testing.T) {
	var (
		err       error
		ok        bool
		req       *http.Request
		resultURL *url.URL
		resultReq *http.Request

		requestContext *GitRequestContext
	)

	testPath := "project/repo"

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/%s/test?served=false&task=true", host, testPath), nil)
	repoContext := getRepoContext(&url.URL{
		Host: req.Host,
		Path: testPath,
	})
	require.NotNil(t, repoContext)

	repoPath := filepath.Join(cachePath, repoContext.hash)
	os.RemoveAll(repoPath)
	os.MkdirAll(repoPath, os.ModePerm)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Nil(t, requestContext.upstream)

	taskIface, ok := repoContext.ext["task"]
	require.True(t, ok)

	task := taskIface.(*utils.Task)
	err = task.Wait(3 * time.Second)
	require.Nil(t, err)

	data, err := ioutil.ReadFile(filepath.Join(repoPath, "test.txt"))
	require.Nil(t, err)
	require.Equal(t, "I am a successful test result\n", string(data))
	os.RemoveAll(repoPath)
}

func TestGitCacheReLaunchBusyTask(t *testing.T) {
	var (
		err       error
		ok        bool
		req       *http.Request
		resultURL *url.URL
		resultReq *http.Request

		requestContext *GitRequestContext
	)

	testPath := "project/repo2"

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/%s/test?served=false&task=true&updated=10s", host, testPath), nil)
	repoContext := getRepoContext(&url.URL{
		Host: req.Host,
		Path: testPath,
	})
	require.NotNil(t, repoContext)

	repoPath := filepath.Join(cachePath, repoContext.hash)
	os.RemoveAll(repoPath)
	os.MkdirAll(repoPath, os.ModePerm)

	log.Debug().Msg(repoPath)

	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Nil(t, requestContext.upstream)

	time.Sleep(500 * time.Millisecond)

	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	errIface, ok := repoContext.ext["err"]
	require.True(t, ok)
	err = errIface.(error)
	require.True(t, errors.Is(err, utils.ErrTaskNotExpired))

	taskIface, ok := repoContext.ext["task"]
	require.True(t, ok)
	task := taskIface.(*utils.Task)

	err = task.Wait(3 * time.Second)
	require.Nil(t, err)

	data, err := ioutil.ReadFile(filepath.Join(repoPath, "test.txt"))
	require.Nil(t, err)
	require.Equal(t, "I am a successful test result\n", string(data))

	os.RemoveAll(repoPath)
}
