package ui

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	os.Chdir("../")
	// Unmount first in case a previous FUSE mount is still active — this
	// never touches OneDrive content, it only detaches the local mountpoint.
	exec.Command("fusermount3", "-uz", "mount").Run()
	os.RemoveAll("mount")
	os.Mkdir("mount", 0700)
	os.Exit(m.Run())
}
