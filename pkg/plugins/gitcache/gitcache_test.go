package gitcache

import (
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
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

var (
	self       plugins.Plugin
	pluginName = utils.PackageAsName()

	host      = "testhost.org"
	cachePath = "/tmp/gitcache/test"

	opts = &options.OptionValue{}
)

func init() {
	SetupLogging("debug")

	self = plugins.PluginBuilder[pluginName]()

	opts.Set("hosts", []string{host})
	opts.Set("cache.path", cachePath)

	if err := os.RemoveAll(cachePath); err != nil {
		log.Panic().Msgf("faillure to remove: %s", cachePath)
	}

	if err := self.Init(opts); err != nil {
		log.Panic().Msgf("init failure: %+v", err)
	}

	selfgch := self.(*GitCacheHandler)
	// selfgch.r.HandleFunc("/test", testRoute)
	selfgch.r.HandleFunc(`/{path:.*?}/test`, testRoute)
}

func testRoute(w http.ResponseWriter, r *http.Request) {
	var (
		ok             bool
		requestContext *GitRequestContext
	)

	urlQuery := r.URL.Query()
	isServedLocal := urlQuery.Get("served")
	isLaunchingTask := urlQuery.Get("task")

	if requestContext, ok = r.Context().Value(reqContextKey).(*GitRequestContext); !ok {
		log.Panic().Msgf("unable to retrieve git cache context for this request: %s", r.URL.String())
	}

	if isServedLocal == "true" {
		requestContext.status = http.StatusOK
	} else {
		requestContext.status = http.StatusNotFound
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

		if err := repoContext.task.SetFunction(func(ctx interface{}) error {
			cmd := command.NewCommand("/bin/bash", "-c", fmt.Sprintf("sleep 2; echo \"I am a successful test result\" >> %s", filepath.Join(testRoot, repoContext.hash, "test.txt")))
			if err := cmd.Run(5*time.Second, nil, nil, ""); err != nil {
				log.Panic().Err(err).Msgf("command run test failure")
			}
			return nil
		}); err != nil {
			repoContext.task.Err = err
			log.Warn().Err(err).Msg("command run test failure")
		} else if err := repoContext.task.Run(nil); err != nil {
			repoContext.task.Err = err
			log.Warn().Err(err).Msg("command run test failure")
		}
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

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/sample/project.git/info/refs?service=git-upload-pack", host), nil)
	resp = httptest.NewRecorder()

	err = self.HandleResponse(resp, req, nil, http.StatusOK)
	require.Nil(t, err)

	res := resp.Result()
	require.NotEqual(t, http.StatusNotFound, res.StatusCode)
}

func TestGitCacheMethodHead(t *testing.T) {
	var (
		err  error
		req  *http.Request
		resp *httptest.ResponseRecorder
	)

	// Requesting HEAD
	req = httptest.NewRequest(http.MethodHead, fmt.Sprintf("http://%s/sample/project.git/info/refs?service=git-upload-pack", host), nil)
	resp = httptest.NewRecorder()

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

	upstreamPath := "https://upstream.org/project.git/info/refs?service=git-upload-pack"

	// Test 1.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/local/path/not/found", host), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, http.StatusNotFound, requestContext.status)
	require.Nil(t, requestContext.upstream)

	// Test 2.
	encodedUpstreamPath := url.QueryEscape(upstreamPath)
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/local/path/not/found?upstream=%s", host, encodedUpstreamPath), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Equal(t, upstreamPath, resultURL.String())
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, http.StatusNotFound, requestContext.status)
	require.Equal(t, upstreamPath, requestContext.upstream.String())

	// Test 3.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test?served=true", host), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, http.StatusOK, requestContext.status)
	require.Nil(t, requestContext.upstream)

	// Test 4.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test?served=true&upstream=%s", host, encodedUpstreamPath), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, http.StatusOK, requestContext.status)
	require.Equal(t, upstreamPath, requestContext.upstream.String())

	// Test 5.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test?served=false", host), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, http.StatusNotFound, requestContext.status)
	require.Nil(t, requestContext.upstream)

	// Test 6.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test?served=false&upstream=%s", host, encodedUpstreamPath), nil)
	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Equal(t, upstreamPath, resultURL.String())
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, http.StatusNotFound, requestContext.status)
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
	require.Equal(t, http.StatusNotFound, requestContext.status)
	require.Nil(t, requestContext.upstream)

	err = repoContext.task.Wait(3 * time.Second)
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

	log.Debug().Msg(repoPath)

	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	requestContext, ok = resultReq.Context().Value(reqContextKey).(*GitRequestContext)
	require.True(t, ok)
	require.Equal(t, http.StatusNotFound, requestContext.status)
	require.Nil(t, requestContext.upstream)

	time.Sleep(500 * time.Millisecond)

	resultURL, resultReq, err = self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultURL)
	require.NotNil(t, resultReq)

	require.True(t, errors.Is(repoContext.task.Err, utils.ErrLockBusy))
	err = repoContext.task.Wait(3 * time.Second)
	require.Nil(t, err)

	data, err := ioutil.ReadFile(filepath.Join(repoPath, "test.txt"))
	require.Nil(t, err)
	require.Equal(t, "I am a successful test result\n", string(data))
	err = repoContext.task.Wait(3 * time.Second)
	require.Nil(t, err)
	os.RemoveAll(repoPath)
}
