// Package integration provides an end-to-end test that:
//   - builds a Docker image containing the webpasswd binary and the
//     provided systemd unit (webpasswd.service),
//   - starts the container with systemd as PID 1 so that the binary runs
//     under exactly the same capability and filesystem-hardening constraints
//     defined in the unit file, and
//   - verifies that a password change is accepted only when the correct
//     current password is supplied.
//
// Run with:
//
//	go test -v -timeout 5m ./integration/
package integration_test

import (
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	imageName     = "webpasswd-integration-test"
	containerName = "webpasswd-integration-test"

	// hostPort is the port mapped to the container's 8080 (as configured in
	// the systemd unit).  Using a high port reduces the chance of conflicts.
	hostPort = "18080"

	// Test user credentials.  Passwords are kept simple because the
	// Dockerfile installs a minimal PAM stack without complexity checking.
	testUser    = "webtest"
	initialPass = "OldPass1234"
	newPass     = "NewPass5678"
	finalPass   = "FinalPass90"
)

// TestPasswordChangeRequiresCorrectCurrentPassword exercises the live
// webpasswd service running under its systemd unit and asserts that:
//
//  1. A change attempt using the wrong current password is rejected.
//  2. A change attempt using the correct current password succeeds.
//  3. After the change, the previous password is no longer accepted.
//  4. After the change, the new password is accepted for a further change.
func TestPasswordChangeRequiresCorrectCurrentPassword(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not found in PATH: %v", err)
	}

	// ----------------------------------------------------------------
	// Build the Docker image.
	// The Dockerfile lives in this (integration/) directory; the build
	// context is the repository root one level up.
	// ----------------------------------------------------------------
	t.Log("Building Docker image (may take a few minutes on first run)…")
	mustRun(t, "docker", "build",
		"-f", "Dockerfile",
		"-t", imageName,
		"..",
	)

	// ----------------------------------------------------------------
	// Start the container with systemd as PID 1.
	// --privileged grants the kernel capabilities that systemd requires
	// (namespaces, cgroup management, bind mounts for ProtectSystem=strict,
	// etc.) as well as the CAP_DAC_* capabilities declared in the unit.
	// ----------------------------------------------------------------

	// Remove any leftover container from a previous aborted run.
	exec.Command("docker", "rm", "-f", containerName).Run() //nolint:errcheck

	t.Cleanup(func() {
		exec.Command("docker", "stop", containerName).Run() //nolint:errcheck
		exec.Command("docker", "rm", containerName).Run()   //nolint:errcheck
	})

	mustRun(t, "docker", "run", "-d",
		"--privileged",
		"--name", containerName,
		"-p", hostPort+":8080",
		imageName,
	)

	// ----------------------------------------------------------------
	// Give systemd a moment to initialise before exec-ing into the
	// container (filesystem mounts, journal socket, etc.).
	// ----------------------------------------------------------------
	t.Log("Waiting for systemd to initialise…")
	time.Sleep(4 * time.Second)

	// ----------------------------------------------------------------
	// Poll the HTTP endpoint until webpasswd is ready (up to 60 s).
	// ----------------------------------------------------------------
	baseURL := "http://localhost:" + hostPort

	t.Log("Waiting for webpasswd to accept connections…")
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(baseURL + "/")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			// Dump service status to help diagnose CI failures.
			out, _ := exec.Command("docker", "exec", containerName,
				"systemctl", "status", "webpasswd").CombinedOutput()
			t.Fatalf("webpasswd did not become ready within 60 s: %v\n%s", err, out)
		}
		time.Sleep(time.Second)
	}

	// ----------------------------------------------------------------
	// Test 1 – wrong current password must be rejected.
	// ----------------------------------------------------------------
	t.Run("WrongCurrentPassword", func(t *testing.T) {
		body := postChange(t, baseURL, testUser, "wrong-password-!", newPass)
		if !strings.Contains(body, "incorrect") {
			t.Errorf("expected 'incorrect' in response; got:\n%s", body)
		}
	})

	// ----------------------------------------------------------------
	// Test 2 – correct current password must succeed.
	// ----------------------------------------------------------------
	t.Run("CorrectCurrentPassword", func(t *testing.T) {
		body := postChange(t, baseURL, testUser, initialPass, newPass)
		if !strings.Contains(body, "successfully") {
			t.Errorf("expected 'successfully' in response; got:\n%s", body)
		}
	})

	// ----------------------------------------------------------------
	// Test 3 – old password is rejected after the change.
	// ----------------------------------------------------------------
	t.Run("OldPasswordRejectedAfterChange", func(t *testing.T) {
		body := postChange(t, baseURL, testUser, initialPass, finalPass)
		if !strings.Contains(body, "incorrect") {
			t.Errorf("expected 'incorrect' after supplying the old password; got:\n%s", body)
		}
	})

	// ----------------------------------------------------------------
	// Test 4 – new password is accepted after the change.
	// ----------------------------------------------------------------
	t.Run("NewPasswordAcceptedAfterChange", func(t *testing.T) {
		body := postChange(t, baseURL, testUser, newPass, finalPass)
		if !strings.Contains(body, "successfully") {
			t.Errorf("expected 'successfully' when supplying the new password; got:\n%s", body)
		}
	})
}

// postChange submits a password-change form to the live service and
// returns the HTML response body.
func postChange(t *testing.T, baseURL, username, currentPwd, newPwd string) string {
	t.Helper()
	form := url.Values{
		"username":             {username},
		"current_password":     {currentPwd},
		"new_password":         {newPwd},
		"new_password_confirm": {newPwd},
	}
	resp, err := http.PostForm(baseURL+"/", form)
	if err != nil {
		t.Fatalf("HTTP POST failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return string(body)
}

// mustRun executes a host command and fails the test if it exits non-zero.
func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command %v failed: %v\n%s", append([]string{name}, args...), err, out)
	}
}
