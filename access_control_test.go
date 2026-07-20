package bleeplab

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func sessionHeaders(sessionID string) map[string]string {
	return map[string]string{"Cookie": shauthSessionCookie + "=" + sessionID}
}

func TestSHAUTHControlPlaneAPIFailsClosedAndAcceptsAuthorizedRoles(t *testing.T) {
	for _, role := range []string{"developer", "admin"} {
		t.Run(role, func(t *testing.T) {
			configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
			s := NewServer(":0", zerolog.Nop())
			ts := httptest.NewServer(s.Handler())
			t.Cleanup(ts.Close)

			for _, request := range []struct {
				method string
				path   string
				body   any
			}{
				{http.MethodPost, "/api/v4/user/runners", map[string]any{"runner_type": "project_type"}},
				{http.MethodPost, "/api/v4/projects", map[string]any{"name": "unauthorized"}},
				{http.MethodPost, "/api/v4/projects/1/repository/commits", map[string]any{"branch": "main"}},
				{http.MethodPost, "/api/v4/projects/1/pipeline", map[string]any{"ref": "main"}},
				{http.MethodGet, "/api/v4/projects/1/pipelines", nil},
				{http.MethodGet, "/api/v4/projects/1/pipelines/1", nil},
				{http.MethodGet, "/api/v4/projects/1/pipelines/1/jobs", nil},
				{http.MethodGet, "/api/v4/projects/1/jobs/1/trace", nil},
			} {
				response, body := do(t, ts, request.method, request.path, request.body, nil)
				if response.StatusCode != http.StatusUnauthorized || response.Header.Get("Content-Type") != "application/json" || !strings.Contains(string(body), "401 Unauthorized") {
					t.Fatalf("unauthenticated %s %s = %d %q %s", request.method, request.path, response.StatusCode, response.Header.Get("Content-Type"), body)
				}
			}
			if len(s.projects) != 0 || len(s.runners) != 0 || len(s.pipelines) != 0 {
				t.Fatalf("unauthenticated requests mutated state: projects=%d runners=%d pipelines=%d", len(s.projects), len(s.runners), len(s.pipelines))
			}

			unauthorizedRole := createTestSession(t, s, func(session *shauthSession) { session.Role = "reporter" })
			response, _ := do(t, ts, http.MethodPost, "/api/v4/projects", map[string]any{"name": "reporter-project"}, sessionHeaders(unauthorizedRole))
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("unsupported role = %d, want 401", response.StatusCode)
			}

			sessionID := createTestSession(t, s, func(session *shauthSession) { session.Role = role })
			headers := sessionHeaders(sessionID)
			response, body := do(t, ts, http.MethodPost, "/api/v4/projects", map[string]any{"name": role + "-project"}, headers)
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("create project = %d: %s", response.StatusCode, body)
			}
			var project struct {
				ID int `json:"id"`
			}
			mustJSON(t, body, &project)

			ci := "stages: [test]\naccess-control:\n  stage: test\n  script: [echo secured]\n"
			response, body = do(t, ts, http.MethodPost, "/api/v4/projects/"+strconv.Itoa(project.ID)+"/repository/commits", map[string]any{
				"branch":  "main",
				"actions": []map[string]string{{"file_path": ".gitlab-ci.yml", "content": ci}},
			}, headers)
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("commit project = %d: %s", response.StatusCode, body)
			}

			response, body = do(t, ts, http.MethodPost, "/api/v4/user/runners", map[string]any{"runner_type": "project_type"}, headers)
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("create runner = %d: %s", response.StatusCode, body)
			}
			var runner struct {
				Token string `json:"token"`
			}
			mustJSON(t, body, &runner)
			if runner.Token == "" {
				t.Fatal("control-plane runner creation returned an empty token")
			}

			response, body = do(t, ts, http.MethodPost, "/api/v4/projects/"+strconv.Itoa(project.ID)+"/pipeline", map[string]any{"ref": "main"}, headers)
			if response.StatusCode != http.StatusCreated {
				t.Fatalf("create pipeline = %d: %s", response.StatusCode, body)
			}
			var pipeline struct {
				ID int `json:"id"`
			}
			mustJSON(t, body, &pipeline)

			for _, path := range []string{
				"/api/v4/projects/" + strconv.Itoa(project.ID) + "/pipelines",
				"/api/v4/projects/" + strconv.Itoa(project.ID) + "/pipelines/" + strconv.Itoa(pipeline.ID),
				"/api/v4/projects/" + strconv.Itoa(project.ID) + "/pipelines/" + strconv.Itoa(pipeline.ID) + "/jobs",
			} {
				response, body = do(t, ts, http.MethodGet, path, nil, headers)
				if response.StatusCode != http.StatusOK {
					t.Fatalf("authorized GET %s = %d: %s", path, response.StatusCode, body)
				}
			}
		})
	}
}

func TestGitLabMachineRoutesRequireNativeTokensWithoutSHAUTHSession(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	t.Setenv("BLEEPLAB_RUNNER_REGISTRATION_TOKEN", "instance-registration-token")
	s := NewServer(":0", zerolog.Nop())
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	for _, presented := range []string{"", "wrong-registration-token"} {
		response, _ := do(t, ts, http.MethodPost, "/api/v4/runners", map[string]any{"token": presented}, nil)
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("legacy registration token %q = %d, want 403", presented, response.StatusCode)
		}
	}
	response, body := do(t, ts, http.MethodPost, "/api/v4/runners", map[string]any{"token": "instance-registration-token"}, nil)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("legacy runner registration = %d: %s", response.StatusCode, body)
	}
	var registered struct {
		Token string `json:"token"`
	}
	mustJSON(t, body, &registered)
	response, body = do(t, ts, http.MethodPost, "/api/v4/runners/verify", map[string]any{"token": registered.Token}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("runner verify = %d: %s", response.StatusCode, body)
	}
	response, body = do(t, ts, http.MethodPost, "/api/v4/jobs/request", map[string]any{"token": registered.Token}, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("runner poll = %d: %s", response.StatusCode, body)
	}
	response, _ = do(t, ts, http.MethodDelete, "/api/v4/runners", map[string]any{"token": "wrong-runner-token"}, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unregister with wrong token = %d, want 403", response.StatusCode)
	}
	response, body = do(t, ts, http.MethodDelete, "/api/v4/runners", map[string]any{"token": registered.Token}, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("runner unregister = %d: %s", response.StatusCode, body)
	}

	sessionID := createTestSession(t, s)
	headers := sessionHeaders(sessionID)
	_, body = do(t, ts, http.MethodPost, "/api/v4/projects", map[string]any{"name": "machine-auth"}, headers)
	var project struct {
		ID int `json:"id"`
	}
	mustJSON(t, body, &project)
	ci := "stages: [test]\nmachine-auth:\n  stage: test\n  script: [echo secured]\n"
	do(t, ts, http.MethodPost, "/api/v4/projects/"+strconv.Itoa(project.ID)+"/repository/commits", map[string]any{
		"branch": "main", "actions": []map[string]string{{"file_path": ".gitlab-ci.yml", "content": ci}},
	}, headers)
	_, body = do(t, ts, http.MethodPost, "/api/v4/user/runners", map[string]any{"runner_type": "project_type"}, headers)
	var runner struct {
		Token string `json:"token"`
	}
	mustJSON(t, body, &runner)
	do(t, ts, http.MethodPost, "/api/v4/projects/"+strconv.Itoa(project.ID)+"/pipeline", map[string]any{"ref": "main"}, headers)
	job := claimJob(t, ts, runner.Token)

	for _, token := range []string{"", "wrong-job-token"} {
		request, err := http.NewRequest(http.MethodPatch, ts.URL+"/api/v4/jobs/"+strconv.Itoa(job.ID)+"/trace", strings.NewReader("unauthorized"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("JOB-TOKEN", token)
		response, err = ts.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("trace token %q = %d, want 403", token, response.StatusCode)
		}
	}
	request, err := http.NewRequest(http.MethodPatch, ts.URL+"/api/v4/jobs/"+strconv.Itoa(job.ID)+"/trace", strings.NewReader("authorized trace\n"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("JOB-TOKEN", job.Token)
	request.Header.Set("Content-Range", "0-17")
	response, err = ts.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("authorized trace = %d", response.StatusCode)
	}

	for _, token := range []string{"", "wrong-job-token"} {
		request, err = http.NewRequest(http.MethodPost, ts.URL+"/api/v4/jobs/"+strconv.Itoa(job.ID)+"/artifacts", strings.NewReader("archive"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("JOB-TOKEN", token)
		response, err = ts.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("artifact token %q = %d, want 403", token, response.StatusCode)
		}
	}
	request, err = http.NewRequest(http.MethodPost, ts.URL+"/api/v4/jobs/"+strconv.Itoa(job.ID)+"/artifacts", strings.NewReader("archive"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("JOB-TOKEN", job.Token)
	response, err = ts.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("authorized artifact upload = %d", response.StatusCode)
	}
	for _, token := range []string{"", "wrong-job-token"} {
		request, err = http.NewRequest(http.MethodGet, ts.URL+"/api/v4/jobs/"+strconv.Itoa(job.ID)+"/artifacts", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("JOB-TOKEN", token)
		response, err = ts.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("artifact download token %q = %d, want 403", token, response.StatusCode)
		}
	}
	request, err = http.NewRequest(http.MethodGet, ts.URL+"/api/v4/jobs/"+strconv.Itoa(job.ID)+"/artifacts", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("JOB-TOKEN", job.Token)
	response, err = ts.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(downloaded) != "archive" {
		t.Fatalf("authorized artifact download = %d %q", response.StatusCode, downloaded)
	}

	response, body = do(t, ts, http.MethodPut, "/api/v4/jobs/"+strconv.Itoa(job.ID), map[string]any{"state": "success"}, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("job update without token = %d: %s", response.StatusCode, body)
	}
	response, body = do(t, ts, http.MethodPut, "/api/v4/jobs/"+strconv.Itoa(job.ID), map[string]any{"token": job.Token, "state": "success"}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authorized job update = %d: %s", response.StatusCode, body)
	}

	if got := s.jobs[job.ID].traceString(); got != "authorized trace\n" {
		t.Fatalf("unauthorized trace data reached storage: %q", got)
	}
}

func TestGitLabMachineRouteClassificationDefaultsToProtected(t *testing.T) {
	for _, test := range []struct {
		method  string
		path    string
		machine bool
	}{
		{http.MethodPost, "/api/v4/jobs/request", true},
		{http.MethodPut, "/api/v4/jobs/42", true},
		{http.MethodPatch, "/api/v4/jobs/42/trace", true},
		{http.MethodGet, "/api/v4/jobs/42/artifacts", true},
		{http.MethodPost, "/api/v4/jobs/42/artifacts", true},
		{http.MethodGet, "/api/v4/projects/42/pipelines", false},
		{http.MethodPost, "/api/v4/user/runners", false},
		{http.MethodGet, "/api/v4/future-control-plane-route", false},
		{http.MethodGet, "/api/v4/jobs/not-a-number/artifacts", false},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		if got := isGitLabMachineAPIRequest(request); got != test.machine {
			t.Errorf("%s %s machine=%t, want %t", test.method, test.path, got, test.machine)
		}
	}
}
