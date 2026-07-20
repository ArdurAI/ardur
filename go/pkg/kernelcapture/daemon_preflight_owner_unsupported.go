//go:build !unix

package kernelcapture

func daemonPreflightFileOwner(_ any) (int, int) {
	return -1, -1
}
