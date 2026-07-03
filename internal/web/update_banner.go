package web

// updateBannerView is the global banner shown on every authenticated page when a
// newer Mooring exists or — critically — when the running version is affected by a
// published security advisory.
type updateBannerView struct {
	Security bool   // true = critical security advisory (red, cannot be missed)
	Message  string // human-readable, already composed
	URL      string // link to the release or advisory (external, opens in a new tab)
}

// updateBanner derives the banner from the update checker's latest posture, or nil
// when the check is disabled/incomplete or there's nothing to show. The security
// advisory takes precedence over a plain update-available.
func (s *Server) updateBanner() *updateBannerView {
	if s.updateCheck == nil {
		return nil
	}
	st := s.updateCheck.State()
	if st == nil || !st.Checked {
		return nil
	}
	if a := st.Advisory; a != nil {
		patched := a.Patched
		if patched == "" {
			patched = "the latest release"
		}
		msg := "Security advisory " + a.GHSAID + " (" + a.Severity + ") affects your Mooring " + st.RunningVersion +
			" — update to " + patched + " immediately."
		return &updateBannerView{Security: true, Message: msg, URL: a.URL}
	}
	if st.UpdateAvailable {
		msg := "Mooring " + st.LatestVersion + " is available (you're on " + st.RunningVersion + ")."
		return &updateBannerView{Message: msg, URL: st.LatestURL}
	}
	return nil
}
