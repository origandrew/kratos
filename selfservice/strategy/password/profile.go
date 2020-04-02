package password

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"

	"github.com/ory/x/sqlxx"

	"github.com/ory/herodot"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/urlx"

	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow/profile"
	"github.com/ory/kratos/selfservice/form"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

const (
	ProfilePath = "/self-service/browser/flows/profile/strategies/password"
)

var (
	continuityKeyProfile = fmt.Sprintf("%x", sha256.Sum256([]byte(ProfilePath)))
)

func (s *Strategy) RegisterProfileManagementRoutes(router *x.RouterPublic) {
	router.POST(ProfilePath, s.completeProfileManagementFlow)
}

func (s *Strategy) ProfileManagementStrategyID() string {
	return string(identity.CredentialsTypePassword)
}

// swagger:model completeSelfServiceBrowserProfileManagementPasswordStrategyFlowPayload
type completeSelfServiceBrowserProfileManagementFlowPayload struct {
	// Password is the updated password
	//
	// type: string
	// required: true
	Password string `json:"password"`

	// RequestID is request ID.
	//
	// in: query
	RequestID string `json:"request_id"`
}

// swagger:route POST /self-service/browser/flows/profile/strategies/profile public completeSelfServiceBrowserProfileManagementPasswordStrategyFlow
//
// Complete the browser-based profile management flow for the password strategy
//
// This endpoint completes a browser-based profile management flow. This is usually achieved by POSTing data to this
// endpoint.
//
// > This endpoint is NOT INTENDED for API clients and only works with browsers (Chrome, Firefox, ...) and HTML Forms.
//
// More information can be found at [ORY Kratos Profile Management Documentation](https://www.ory.sh/docs/next/kratos/self-service/flows/user-profile-management).
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       302: emptyResponse
//       500: genericError
func (s *Strategy) completeProfileManagementFlow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ss, err := s.d.SessionManager().FetchFromRequest(r.Context(), w, r)
	if err != nil {
		s.handleProfileManagementError(w, r, nil, nil, err)
		return
	}

	rid := r.URL.Query().Get("request")
	if len(rid) == 0 {
		s.handleProfileManagementError(w, r, nil, ss.Identity.Traits, errors.WithStack(herodot.ErrBadRequest.WithReasonf("The request query parameter is missing.")))
		return
	}

	if err := r.ParseForm(); err != nil {
		s.handleProfileManagementError(w, r, nil, ss.Identity.Traits, errors.WithStack(err))
		return
	}

	p := completeSelfServiceBrowserProfileManagementFlowPayload{
		RequestID: rid,
		Password:  r.PostFormValue("password"),
	}
	if err := s.d.ContinuityManager().Pause(
		r.Context(), w, r,
		continuityKeyProfile,
		continuity.WithPayload(&p),
		continuity.WithIdentity(ss.Identity),
		continuity.WithLifespan(time.Minute*15),
	); err != nil {
		s.handleProfileManagementError(w, r, nil, ss.Identity.Traits, errors.WithStack(err))
		return
	}

	s.CompleteProfileManagementFlow(w, r, ss)
}

func (s *Strategy) CompleteProfileManagementFlow(w http.ResponseWriter, r *http.Request, ss *session.Session) {
	var p completeSelfServiceBrowserProfileManagementFlowPayload
	if _, err := s.d.ContinuityManager().Continue(r.Context(), r,
		continuityKeyProfile,
		continuity.WithIdentity(ss.Identity),
		continuity.WithPayload(&p),
	); err != nil {
		s.handleProfileManagementError(w, r, nil, ss.Identity.Traits, err)
		return
	}

	ar, err := s.d.ProfileRequestPersister().GetProfileRequest(r.Context(), x.ParseUUID(p.RequestID))
	if err != nil {
		s.handleProfileManagementError(w, r, nil, ss.Identity.Traits, err)
		return
	}

	if err := ar.Valid(ss); err != nil {
		s.handleProfileManagementError(w, r, ar, ss.Identity.Traits, err)
		return
	}

	if ss.AuthenticatedAt.Add(s.c.SelfServicePrivilegedSessionMaxAge()).Before(time.Now()) {
		s.handleProfileManagementError(w, r, nil, ss.Identity.Traits, errors.WithStack(profile.ErrRequestNeedsReAuthentication))
		return
	}

	if len(p.Password) == 0 {
		s.handleProfileManagementError(w, r, ar, ss.Identity.Traits, schema.NewRequiredError("#/", "password"))
		return
	}

	hpw, err := s.d.PasswordHasher().Generate([]byte(p.Password))
	if err != nil {
		s.handleProfileManagementError(w, r, ar, ss.Identity.Traits, err)
		return
	}

	co, err := json.Marshal(&CredentialsConfig{HashedPassword: string(hpw)})
	if err != nil {
		s.handleProfileManagementError(w, r, ar, ss.Identity.Traits, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to encode password options to JSON: %s", err)))
		return
	}

	i, err := s.d.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), ss.Identity.ID)
	if err != nil {
		s.handleProfileManagementError(w, r, ar, ss.Identity.Traits, err)
		return
	}

	c, ok := i.GetCredentials(s.ID())
	if !ok {
		c = &identity.Credentials{Type: s.ID(),
			// Prevent duplicates
			Identifiers: []string{x.NewUUID().String()}}
	}

	c.Config = co
	i.SetCredentials(s.ID(), *c)
	if err := s.validateCredentials(i, p.Password); err != nil {
		s.handleProfileManagementError(w, r, ar, ss.Identity.Traits, err)
		return
	}

	if err := s.d.ProfileManagementExecutor().PostProfileManagementHook(w, r,
		s.d.PostProfileManagementHooks(profile.StrategyTraitsID),
		ar, ss, i,
	); errorsx.Cause(err) == profile.ErrHookAbortRequest {
		return
	} else if err != nil {
		s.handleProfileManagementError(w, r, ar, ss.Identity.Traits, err)
		return
	}

	if len(w.Header().Get("Location")) == 0 {
		http.Redirect(w, r,
			urlx.CopyWithQuery(s.c.ProfileURL(), url.Values{"request": {ar.ID.String()}}).String(),
			http.StatusFound,
		)
	}
}

func (s *Strategy) PopulateProfileManagementMethod(r *http.Request, ss *session.Session, pr *profile.Request) error {
	disabled := ss.AuthenticatedAt.Add(s.c.SelfServicePrivilegedSessionMaxAge()).Before(time.Now())

	f := &form.HTMLForm{
		Action: urlx.CopyWithQuery(
			urlx.AppendPaths(s.c.SelfPublicURL(), ProfilePath),
			url.Values{"request": {pr.ID.String()}},
		).String(),
		Method: "POST",
		Fields: form.Fields{
			{
				Name:     "password",
				Type:     "password",
				Required: true,
				Disabled: disabled,
			},
		},
	}
	f.SetCSRF(s.d.GenerateCSRFToken(r))

	pr.Methods[string(s.ID())] = &profile.RequestMethod{
		Method: string(s.ID()),
		Config: &profile.RequestMethodConfig{RequestMethodConfigurator: &RequestMethod{HTMLForm: f}},
	}
	pr.Active = sqlxx.NullString(s.ID())
	return nil
}

func (s *Strategy) handleProfileManagementError(w http.ResponseWriter, r *http.Request, rr *profile.Request, traits identity.Traits, err error) {
	if rr != nil {
		rr.Methods[s.ProfileManagementStrategyID()].Config.Reset()
		rr.Methods[s.ProfileManagementStrategyID()].Config.SetCSRF(s.d.GenerateCSRFToken(r))
	}

	s.d.ProfileRequestRequestErrorHandler().HandleProfileManagementError(w, r, rr, err, string(identity.CredentialsTypePassword))
}
