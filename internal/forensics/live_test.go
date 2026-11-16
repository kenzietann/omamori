package forensics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/pathguard"
)

func TestReadPlacesCoverEveryPatternAndScanFolder(t *testing.T) {
	places := ReadPlaces()
	have := map[string]bool{}
	for _, place := range places {
		have[place] = true
	}
	for _, want := range []string{
		"var/log", "var/log/nginx", "var/log/apache2", "var/log/httpd", "etc", "etc/cron.d", "var/spool/cron",
		"var/spool/cron/crontabs", "etc/systemd/system", "root", "root/.ssh", "home", "tmp", "var/tmp", "dev/shm",
		"var/www", "srv", "opt", "usr/local/bin",
	} {
		if !have[want] {
			t.Errorf("%q is read but is not in the places: %v", want, places)
		}
	}
	for _, place := range places {
		if place == "" || place == "." || strings.HasPrefix(place, "/") || strings.Contains(place, "*") {
			t.Errorf("a place that is not a clean relative folder: %q", place)
		}
	}
	// Every file that a pattern names lies inside a place, so a report outside the places cannot be read.
	for _, current := range patterns {
		covered := false
		for _, place := range places {
			if current.glob == place || strings.HasPrefix(current.glob, place+"/") {
				covered = true
			}
		}
		if !covered {
			t.Errorf("the pattern %q is in no place", current.glob)
		}
	}
	// Places that are not read stay free for the report.
	for _, free := range []string{"var/lib/omamori", "mnt", "media", "usr/bin", "proc"} {
		if have[free] {
			t.Errorf("%q is not read, but it is a place", free)
		}
	}
}

func TestIsSystemRoot(t *testing.T) {
	if !IsSystemRoot("/") {
		t.Error("/ is the top of the system")
	}
	directory := t.TempDir()
	if IsSystemRoot(directory) {
		t.Error("a folder is not the top of the system")
	}
	link := filepath.Join(directory, "top")
	if err := os.Symlink("/", link); err != nil {
		t.Skip("no symlinks")
	}
	if !IsSystemRoot(link) {
		t.Error("a link to / is the top of the system")
	}
	if IsSystemRoot(filepath.Join(directory, "missing")) {
		t.Error("a folder that is not there is not the top of the system")
	}
}

func TestLivePlacesAreAbsoluteUnderTheRoot(t *testing.T) {
	for _, place := range LivePlaces("/") {
		if !filepath.IsAbs(place) {
			t.Errorf("not absolute: %q", place)
		}
	}
	got := LivePlaces("/srv/image")
	if len(got) == 0 || !strings.HasPrefix(got[0], "/srv/image/") {
		t.Errorf("places are under the root: %v", got)
	}
}

// The decision that keeps a report out of a running system, without reading the system.
func TestReportFolderOnARunningSystem(t *testing.T) {
	places := LivePlaces("/")
	check := func(output string) error {
		for _, place := range places {
			if err := pathguard.CheckOutputFolder(place, output); err != nil {
				return err
			}
		}

		return nil
	}
	for _, refused := range []string{
		"/tmp/x/forensics-1", "/var/tmp/forensics-1", "/var/log/omamori/forensics-1", "/etc/omamori/forensics-1",
		"/home/someone/reports/forensics-1", "/root/forensics-1", "/root/.ssh/forensics-1", "/opt/omamori/forensics-1",
		"/srv/forensics-1", "/var/www/forensics-1", "/var/spool/cron/forensics-1", "/dev/shm/forensics-1",
	} {
		if check(refused) == nil {
			t.Errorf("%s is read by the run, so a report there must be refused", refused)
		}
	}
	for _, allowed := range []string{
		"/var/lib/omamori/forensics-1", "/mnt/disk/forensics-1", "/media/usb/forensics-1", "/var/forensics-1", "/forensics-1",
	} {
		if err := check(allowed); err != nil {
			t.Errorf("%s is not read by the run, but it was refused: %v", allowed, err)
		}
	}
}
