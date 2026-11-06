package wintun

// Load extracts the embedded wintun.dll below CacheDir, verifies it and loads it for the life of the process, so that
// golang.zx2c4.com/wintun finds it by its base name. Once a call succeeds, later calls do nothing; after a failure, the
// next call tries again. Its errors start with "wintun: "; outside Windows it returns one wrapping errors.ErrUnsupported.
func Load() error {
	return load()
}
