// Xalgorix — Autonomous AI Pentesting Engine
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/tui"
	"github.com/xalgord/xalgorix/v4/internal/web"
)

var version = "4.2.0"

func main() {
	// Top-level crash recovery — catches panics that escape all other handlers.
	// Critical for service mode where stderr may not be visible.
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			crashMsg := fmt.Sprintf(
				"[FATAL CRASH] %v\nHeap: %d MB | Sys: %d MB | Goroutines: %d\n\nStack:\n%s",
				r, m.HeapAlloc/1024/1024, m.Sys/1024/1024, runtime.NumGoroutine(), string(stack),
			)

			// Log to stderr
			fmt.Fprintf(os.Stderr, "\n%s\n", crashMsg)

			// Also log to a file so it survives systemd journal rotation
			if f, err := os.OpenFile("/tmp/xalgorix-crash.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				fmt.Fprintf(f, "\n=== CRASH @ %s ===\n%s\n", time.Now().Format(time.RFC3339), crashMsg)
				f.Close()
			}

			os.Exit(2)
		}
	}()

	args := parseArgs()

	// Handle start command
	if args.start {
		handleStart()
		os.Exit(0)
	}

	// Handle stop command
	if args.stop {
		handleStop()
		os.Exit(0)
	}

	// Handle restart command
	if args.restart {
		handleRestart()
		os.Exit(0)
	}

	// Handle uninstall command
	if args.uninstall {
		handleUninstall()
		os.Exit(0)
	}

	if args.version {
		fmt.Printf("xalgorix v%s\n", version)
		os.Exit(0)
	}

	// Auto-update on startup is OFF by default. It hits the GitHub releases
	// API, which (a) costs a few seconds of latency on every run, (b) gets
	// rate-limited on shared workstations, and (c) silently restarts the
	// process mid-launch which is surprising for an interactive tool.
	// To re-enable, export XALGORIX_AUTOUPDATE=1. Use `xalgorix --update`
	// for an explicit one-shot update.
	if !args.update && os.Getenv("XALGORIX_AUTOUPDATE") == "1" {
		autoUpdate()
	}


	if args.update {
		fmt.Println("Updating xalgorix to latest version...")

		// Fetch latest release info from GitHub
		latestVer, downloadURL := fetchLatestRelease()
		if latestVer == "" {
			fmt.Fprintf(os.Stderr, "❌ Failed to fetch latest version from GitHub\n")
			fmt.Fprintf(os.Stderr, "   This is usually caused by GitHub API rate limiting (60 req/hour for unauthenticated users).\n")
			fmt.Fprintf(os.Stderr, "   Try again in a few minutes, or update manually:\n")
			fmt.Fprintf(os.Stderr, "   wget -O $(which xalgorix) https://github.com/xalgord/xalgorix/releases/latest/download/xalgorix-linux-amd64\n")
			os.Exit(1)
		}

		if latestVer == version {
			fmt.Printf("✅ Already on latest version v%s\n", version)
			os.Exit(0)
		}

		fmt.Printf("Latest version: v%s\n", latestVer)

		// Determine install path
		installPath := resolveInstallPath()

		// Primary: download pre-built binary from GitHub release
		if downloadURL != "" {
			fmt.Printf("Downloading binary from GitHub release...\n")
			if err := installBinary(downloadURL, installPath); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Binary download failed: %v\n", err)
				fmt.Println("Falling back to go install...")
				goto goInstallFallback
			}
			fmt.Println("✅ Updated successfully!")
			verCmd := exec.Command(installPath, "--version")
			verCmd.Stdout = os.Stdout
			verCmd.Run()
			os.Exit(0)
		}

	goInstallFallback:
		// Fallback: use go install with explicit version
		fmt.Printf("Installing v%s via go install...\n", latestVer)
		cmd := exec.Command("go", "install", "-v", "github.com/xalgord/xalgorix/v4/cmd/xalgorix@v"+latestVer)
		cmd.Env = append(os.Environ(),
			"GOPROXY=direct",
			"GONOSUMCHECK=github.com/xalgord/*",
			"GONOSUMDB=github.com/xalgord/*",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Update failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "\nManual install:\n")
			fmt.Fprintf(os.Stderr, "  GOPROXY=direct go install -v github.com/xalgord/xalgorix/v4/cmd/xalgorix@v%s\n", latestVer)
			os.Exit(1)
		}

		// go install puts the binary in $GOPATH/bin — copy it to the actual
		// install path if they differ (e.g. /usr/local/bin vs ~/go/bin).
		goPath := os.Getenv("GOPATH")
		if goPath == "" {
			goPath = filepath.Join(os.Getenv("HOME"), "go")
		}
		goBinPath := filepath.Join(goPath, "bin", "xalgorix")
		if goBinPath != installPath {
			if _, err := os.Stat(goBinPath); err == nil {
				// Try direct copy first, fall back to sudo cp
				cpCmd := exec.Command("cp", goBinPath, installPath)
				if cpErr := cpCmd.Run(); cpErr != nil {
					cpCmd = exec.Command("sudo", "cp", goBinPath, installPath)
					cpCmd.Run()
				}
				os.Chmod(installPath, 0755)
			}
		}

		fmt.Println("✅ Updated successfully!")
		verCmd := exec.Command(installPath, "--version")
		verCmd.Stdout = os.Stdout
		verCmd.Run()
		os.Exit(0)
	}


	cfg := config.Get()

	// Set web package version from main — single source of truth
	web.Version = version

	if args.model != "" {
		cfg.LLM = args.model
	}

	// Web UI mode — no target or API config required at launch
	if args.webUI {

		port := args.port
		if port == 0 {
			port = 1337
		}

		fmt.Print(tui.Banner)
		fmt.Println()
		fmt.Printf("\n  Xalgorix Web UI starting on port %d...\n", port)
		fmt.Printf("  Open http://localhost:%d in your browser\n\n", port)

		srv := web.NewServer(cfg, port)
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// CLI/TUI mode — target required
	if len(args.targets) == 0 {
		fmt.Fprintf(os.Stderr, "Error: at least one --target is required (or use --web for Web UI)\n\n")
		printUsage()
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %s\n\n", err)
		fmt.Fprintf(os.Stderr, "Set your model:     export XALGORIX_LLM='openai/gpt-5.4'\n")
		fmt.Fprintf(os.Stderr, "Set your API key:    export XALGORIX_API_KEY='sk-...'\n")
		os.Exit(1)
	}

	// Default to CLI mode (no TUI)
	tui.RunCLI(cfg, args.targets, args.instruction)
}

type cliArgs struct {
	targets     []string
	instruction string
	model       string
	version     bool
	update      bool
	webUI       bool
	port        int
	start       bool
	stop        bool
	restart     bool
	uninstall   bool
}

func parseArgs() cliArgs {
	var args cliArgs

	osArgs := os.Args[1:]
	for i := 0; i < len(osArgs); i++ {
		switch osArgs[i] {
		case "--target", "-t":
			if i+1 < len(osArgs) {
				i++
				args.targets = append(args.targets, osArgs[i])
			}
		case "--instruction", "-i":
			if i+1 < len(osArgs) {
				i++
				args.instruction = osArgs[i]
			}
		case "--model", "-m":
			if i+1 < len(osArgs) {
				i++
				args.model = osArgs[i]
			}
		case "--port", "-p":
			if i+1 < len(osArgs) {
				i++
				fmt.Sscanf(osArgs[i], "%d", &args.port)
			}
		case "--web", "-w":
			args.webUI = true
		case "--update", "-up":
			args.update = true
		case "--version", "-v":
			args.version = true
		case "--start":
			args.start = true
		case "--stop":
			args.stop = true
		case "--restart":
			args.restart = true
		case "--uninstall":
			args.uninstall = true
		case "--help", "-h":
			printUsage()
			os.Exit(0)
		default:
			if strings.HasPrefix(osArgs[i], "--target=") {
				args.targets = append(args.targets, strings.TrimPrefix(osArgs[i], "--target="))
			} else if strings.HasPrefix(osArgs[i], "--instruction=") {
				args.instruction = strings.TrimPrefix(osArgs[i], "--instruction=")
			} else if strings.HasPrefix(osArgs[i], "--model=") {
				args.model = strings.TrimPrefix(osArgs[i], "--model=")
			} else if strings.HasPrefix(osArgs[i], "--port=") {
				fmt.Sscanf(strings.TrimPrefix(osArgs[i], "--port="), "%d", &args.port)
			}
		}
	}

	return args
}

func printUsage() {
	fmt.Print(tui.Banner)
	fmt.Println()
	fmt.Println()
	fmt.Println("  Autonomous AI Pentesting Engine")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  xalgorix --web                  Start the Web UI (default port 1337)")
	fmt.Println("  xalgorix --target <url> [flags]  Run a scan in CLI mode")
	fmt.Println()
	fmt.Println("Modes:")
	fmt.Println("  -w, --web                 Launch the Web UI dashboard")
	fmt.Println("  -p, --port <port>         Web UI port (default: 1337)")
	fmt.Println()
	fmt.Println("Service Commands:")
	fmt.Println("  --start                   Install and start as systemd service")
	fmt.Println("  --stop                    Stop the service")
	fmt.Println("  --restart                 Restart the service")
	fmt.Println("  --uninstall               Remove from system")
	fmt.Println()
	fmt.Println("CLI Flags:")
	fmt.Println("  -t, --target <url>        Target URL, IP, or local path (repeatable)")
	fmt.Println("  -i, --instruction <text>  Custom instructions for the agent")
	fmt.Println("  -m, --model <name>        LLM model (overrides XALGORIX_LLM)")
	fmt.Println("  -v, --version             Show version")
	fmt.Println("  -up, --update             Update to latest version")
	fmt.Println("  --start                  Start as background service")
	fmt.Println("  --stop                   Stop running service")
	fmt.Println("  --uninstall              Uninstall from system")
	fmt.Println("  -h, --help                Show help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  xalgorix --web")
	fmt.Println("  xalgorix --web --port 8080")
	fmt.Println("  xalgorix --target https://example.com")
	fmt.Println("  xalgorix --target https://example.com --instruction \"Focus on auth\"")
	fmt.Println()
	fmt.Println("Service Commands:")
	fmt.Println("  xalgorix --start      Start Web UI in background")
	fmt.Println("  xalgorix --stop       Stop running Web UI")
	fmt.Println("  xalgorix --uninstall  Remove xalgorix from system")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  XALGORIX_LLM              Model name (e.g. minimax/MiniMax-M2.7)")
	fmt.Println("  XALGORIX_API_KEY           API key")
	fmt.Println("  XALGORIX_API_BASE          API base URL")
	fmt.Println("  XALGORIX_MAX_ITERATIONS    Max iterations (0 = unlimited)")
	fmt.Println()
}

// handleStart installs and starts xalgorix as a systemd service
func handleStart() {
	// Determine install path
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	installPath := filepath.Join(goPath, "bin", "xalgorix")

	// Check if binary exists
	if _, err := os.Stat(installPath); os.IsNotExist(err) {
		fmt.Printf("❌ Xalgorix not found at %s\n", installPath)
		fmt.Println("   Install with: xalgorix --update")
		os.Exit(1)
	}

	// Kill any existing xalgorix processes first (ignore if none running)
	exec.Command("pkill", "-f", "xalgorix.*--web").Run()
	time.Sleep(1 * time.Second)

	// Also kill anything using port 1337 (ignore if port is free)
	exec.Command("fuser", "-k", "1337/tcp").Run()
	time.Sleep(1 * time.Second)

	// Create systemd service file
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	serviceContent := fmt.Sprintf(`[Unit]
Description=Xalgorix - Autonomous AI Pentesting Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
Environment="PATH=%s/go/bin:%s/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="GOPATH=%s/go"
EnvironmentFile=%s/.xalgorix.env
ExecStart=%s --web
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, home, home, home, home, home, installPath)
	// Try to write service file (requires sudo)
	servicePath := "/etc/systemd/system/xalgorix.service"
	err := os.WriteFile(servicePath, []byte(serviceContent), 0644)

	if err != nil {
		// Try with sudo
		cmd := exec.Command("sudo", "tee", servicePath)
		cmd.Stdin = strings.NewReader(serviceContent)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to create service file (need sudo): %v\n", err)
			fmt.Println("   Trying to start in background mode...")
			startBackground()
			return
		}
	}

	// Reload systemd and enable service
	var cmd *exec.Cmd
	cmd = exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: systemctl daemon-reload failed: %v", err)
	}

	cmd = exec.Command("systemctl", "enable", "xalgorix")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Failed to enable service: %v\n", err)
	}

	// Start the service
	cmd = exec.Command("systemctl", "start", "xalgorix")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to start xalgorix service: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Xalgorix installed and started as systemd service!")
	fmt.Println("   Web UI: http://localhost:1337")
	fmt.Println("   Logs:   journalctl -u xalgorix -f")
	fmt.Println("   Status: systemctl status xalgorix")
}

func startBackground() {
	logFile, err := os.OpenFile("/tmp/xalgorix.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to open log file: %v\n", err)
		os.Exit(1)
	}

	// Use GOPATH
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	installPath := filepath.Join(goPath, "bin", "xalgorix")

	// Start via bash to source env file
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}
	startCmd := exec.Command("/bin/bash", "-c", "source "+homeDir+"/.xalgorix.env && "+installPath+" --web")
	startCmd.Stdout = logFile
	startCmd.Stderr = logFile
	startCmd.Env = os.Environ()

	if err := startCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to start xalgorix: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Xalgorix started in background!")
	fmt.Println("   Web UI: http://localhost:1337")
	fmt.Println("   Logs:   tail -f /tmp/xalgorix.log")
	fmt.Printf("   PID:    %d\n", startCmd.Process.Pid)
}

// handleStop stops the xalgorix service
func handleStop() {
	// Try to send stop notification to Discord first
	go func() {
		resp, err := http.Get("http://localhost:1337/api/stop-notify")
		if err == nil {
			resp.Body.Close()
		}
	}()

	// Small delay to let notification send
	time.Sleep(500 * time.Millisecond)

	// Try systemctl first (with sudo)
	cmd := exec.Command("sudo", "systemctl", "stop", "xalgorix")
	err := cmd.Run()

	if err != nil {
		// Fallback: pkill (exclude the current --stop process)
		cmd = exec.Command("pkill", "-f", "xalgorix.*--web")
		cmd.Run()
	}

	fmt.Println("✅ Xalgorix stopped!")
}

// handleRestart restarts the xalgorix service
func handleRestart() {
	// Try systemctl first (with sudo)
	cmd := exec.Command("sudo", "systemctl", "restart", "xalgorix")
	err := cmd.Run()

	if err != nil {
		// Fallback: stop then start
		handleStop()
		startBackground()
		return
	}

	fmt.Println("✅ Xalgorix restarted!")
	fmt.Println("   Web UI: http://localhost:1337")
}

// handleUninstall removes xalgorix from the system
func handleUninstall() {
	fmt.Println("🗑️  Uninstalling Xalgorix...")

	// Stop the service first
	cmd := exec.Command("pkill", "-f", "xalgorix")
	cmd.Run()

	// Determine install path
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	installPath := filepath.Join(goPath, "bin", "xalgorix")

	// Remove binary
	if _, err := os.Stat(installPath); err == nil {
		rmCmd := exec.Command("rm", installPath)
		rmCmd.Stdout = os.Stdout
		rmCmd.Stderr = os.Stderr
		if err := rmCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to remove binary: %v\n", err)
		} else {
			fmt.Printf("✅ Removed %s\n", installPath)
		}
	}

	// Ask about data removal
	fmt.Println()
	fmt.Println("📁 Data directories (not removed automatically):")
	fmt.Println("   ~/.xalgorix/         - Configuration & skills")
	fmt.Println("   ~/xalgorix-data/    - Scan data & reports")
	fmt.Println()
	fmt.Println("To remove data manually:")
	fmt.Println("   rm -rf ~/.xalgorix ~/xalgorix-data")

	fmt.Println()
	fmt.Println("✅ Uninstall complete!")
}

// autoUpdate checks GitHub for a newer release and self-updates if found.
func autoUpdate() {
	latestVer, downloadURL := fetchLatestRelease()
	if latestVer == "" || latestVer == version {
		return
	}

	if !isNewer(latestVer, version) {
		return
	}

	fmt.Printf("\n🔄 New version available: v%s → v%s\n", version, latestVer)

	installPath := resolveInstallPath()

	// Try binary download first (fastest, avoids Go module issues)
	if downloadURL != "" {
		fmt.Println("   Downloading update...")
		if err := installBinary(downloadURL, installPath); err != nil {
			fmt.Printf("   ⚠️  Download failed: %v (run 'xalgorix --update' manually)\n", err)
			return
		}
	} else {
		// Fallback to go install
		fmt.Println("   Installing update via go install...")
		cmd := exec.Command("go", "install", "-v", "github.com/xalgord/xalgorix/v4/cmd/xalgorix@v"+latestVer)
		cmd.Env = append(os.Environ(),
			"GOPROXY=direct",
			"GONOSUMCHECK=github.com/xalgord/*",
			"GONOSUMDB=github.com/xalgord/*",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("   ⚠️  Auto-update failed: %v (run 'xalgorix --update' manually)\n", err)
			return
		}

		// go install puts the binary in $GOPATH/bin — copy to actual install path
		goPath := os.Getenv("GOPATH")
		if goPath == "" {
			goPath = filepath.Join(os.Getenv("HOME"), "go")
		}
		goBinPath := filepath.Join(goPath, "bin", "xalgorix")
		if goBinPath != installPath {
			if _, statErr := os.Stat(goBinPath); statErr == nil {
				cpCmd := exec.Command("cp", goBinPath, installPath)
				if cpErr := cpCmd.Run(); cpErr != nil {
					cpCmd = exec.Command("sudo", "cp", goBinPath, installPath)
					cpCmd.Run()
				}
				os.Chmod(installPath, 0755)
			}
		}
	}

	fmt.Printf("   ✅ Updated to v%s! Restarting...\n\n", latestVer)

	// Re-exec with same args
	execPath, err := os.Executable()
	if err != nil {
		fmt.Printf("   ⚠️  Restart failed: %v (please restart manually)\n", err)
		os.Exit(0)
	}
	execPath, _ = filepath.EvalSymlinks(execPath)
	execErr := execRestart(execPath, os.Args, os.Environ())
	if execErr != nil {
		fmt.Printf("   ⚠️  Restart failed: %v (please restart manually)\n", execErr)
	}
	os.Exit(0)
}

// isNewer returns true if a is newer than b (semver comparison).
func isNewer(a, b string) bool {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	for i := 0; i < len(partsA) && i < len(partsB); i++ {
		var numA, numB int
		fmt.Sscanf(partsA[i], "%d", &numA)
		fmt.Sscanf(partsB[i], "%d", &numB)
		if numA > numB {
			return true
		}
		if numA < numB {
			return false
		}
	}
	return len(partsA) > len(partsB)
}

// execRestart re-executes the current process with the same arguments.
func execRestart(path string, argv, env []string) error {
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	return cmd.Run()
}

// fetchLatestRelease queries GitHub for the latest release version and binary download URL.
func fetchLatestRelease() (version string, downloadURL string) {
	client := &http.Client{Timeout: 15 * time.Second}

	// GitHub API requires User-Agent header; missing it returns 403
	req, err := http.NewRequest("GET", "https://api.github.com/repos/xalgord/xalgorix/releases/latest", nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "xalgorix/"+version)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Update check failed (network): %v", err)
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		// Rate limited — fall back to tags API (lighter quota)
		log.Printf("GitHub API rate limited (HTTP %d), trying tags fallback...", resp.StatusCode)
		return fetchLatestTag(client)
	}

	if resp.StatusCode != 200 {
		log.Printf("GitHub releases API returned HTTP %d", resp.StatusCode)
		return fetchLatestTag(client)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", ""
	}

	ver := strings.TrimPrefix(release.TagName, "v")
	if ver == "" {
		return "", ""
	}

	// Find the binary asset for this OS/arch
	wantName := fmt.Sprintf("xalgorix-%s-%s", runtime.GOOS, runtime.GOARCH)
	for _, asset := range release.Assets {
		if asset.Name == wantName || asset.Name == "xalgorix" {
			return ver, asset.BrowserDownloadURL
		}
	}

	// No binary asset found — return version only (will use go install fallback)
	return ver, ""
}

// fetchLatestTag uses the git tags API as a fallback when releases API is rate-limited.
// Returns only the version (no download URL); caller will use go install or direct download.
func fetchLatestTag(client *http.Client) (string, string) {
	req, err := http.NewRequest("GET", "https://api.github.com/repos/xalgord/xalgorix/tags?per_page=1", nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "xalgorix/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", ""
	}

	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil || len(tags) == 0 {
		return "", ""
	}

	ver := strings.TrimPrefix(tags[0].Name, "v")
	if ver == "" {
		return "", ""
	}

	// Build the direct download URL (known pattern)
	wantName := fmt.Sprintf("xalgorix-%s-%s", runtime.GOOS, runtime.GOARCH)
	downloadURL := fmt.Sprintf("https://github.com/xalgord/xalgorix/releases/download/v%s/%s", ver, wantName)
	return ver, downloadURL
}

// resolveInstallPath determines where the xalgorix binary should be installed.
func resolveInstallPath() string {
	// First: check if we're running from a known path
	if execPath, err := os.Executable(); err == nil {
		execPath, _ = filepath.EvalSymlinks(execPath)
		// If running from GOPATH/bin or /usr/local/bin, install there
		if strings.Contains(execPath, "/go/bin/") || strings.HasPrefix(execPath, "/usr/local/bin/") {
			return execPath
		}
	}
	// Default: GOPATH/bin
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	return filepath.Join(goPath, "bin", "xalgorix")
}

// installBinary downloads a binary from url and installs it to destPath.
// Handles "text file busy" on Linux by removing the old file before moving the new one.
func installBinary(url, destPath string) error {
	// Download to a temporary file next to the destination
	tmpPath := destPath + ".new"
	defer os.Remove(tmpPath) // cleanup on failure

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	_, err = io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		return fmt.Errorf("download interrupted: %w", err)
	}

	// Swap strategy for Linux "text file busy":
	// 1. Remove the old binary (unlinks it from directory; running process keeps its fd)
	// 2. Rename the new binary into place (atomic on same filesystem)
	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		// If remove fails (e.g., permission denied), try rename directly
		// which will fail with ETXTBSY — then try with sudo
		log.Printf("Warning: could not remove old binary: %v, trying rename...", err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		// Last resort: try sudo mv
		cmd := exec.Command("sudo", "mv", tmpPath, destPath)
		if sudoErr := cmd.Run(); sudoErr != nil {
			return fmt.Errorf("failed to install binary (tried mv and sudo mv): %w", err)
		}
	}

	// Ensure executable
	os.Chmod(destPath, 0755)

	return nil
}
