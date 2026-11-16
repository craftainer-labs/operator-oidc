package controller

import (
	"context"
	"errors"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/dcr"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"

	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// keycloakAPI is the part of *idpclient.Keycloak the driver uses; tests
// replace it.
type keycloakAPI interface {
	Get(ctx context.Context, id, marker string) (idpclient.Client, error)
	Create(ctx context.Context, s idpclient.ClientSpec) (idpclient.Client, error)
	Update(ctx context.Context, id string, s idpclient.ClientSpec) error
	Delete(ctx context.Context, id string) error
	Secret(ctx context.Context, id string) (string, error)
	Rotate(ctx context.Context, id, current string) (idpclient.Rotation, error)
	FinishRotation(ctx context.Context, id string) error
}

// keycloakDriver manages a client on Keycloak. status.externalId is Keycloak's
// own id of the client and status.externalName its client_id; the client
// carries the claim's ownership marker.
type keycloakDriver struct {
	base
	k keycloakAPI
	// noOverlap is set when the last rotation killed the previous secret at
	// once. It is false until a rotation says so, so a rotation adopted after a
	// crash keeps its grace period, which only retires a secret that is gone.
	noOverlap bool
}

var _ driver = (*keycloakDriver)(nil)

func (d *keycloakDriver) marker() string {
	return idpclient.Marker(d.claim.Namespace, d.claim.Name, string(d.claim.UID))
}

// spec is the client as the claim wants it, with every default resolved.
func (d *keycloakDriver) spec(w clientSpec) idpclient.ClientSpec {
	return idpclient.ClientSpec{
		ClientID: d.claim.GetExternalName(), Marker: d.marker(), Public: w.public,
		RedirectURIs: w.redirectURIs, PostLogoutRedirectURIs: w.postLogout, WebOrigins: w.webOrigins,
		GrantTypes: w.grants, PKCE: w.pkce, Scopes: w.scopes,
	}
}

// observe reads the client by the id in status, never by its name. A claim with
// no id has made nothing yet: Create adopts a client of its name that carries
// its marker, and refuses one that does not.
func (d *keycloakDriver) observe(ctx context.Context, w clientSpec, wantErr error) (lifecycle.Observation[clientState], error) {
	none := lifecycle.Observation[clientState]{}
	id := d.claim.GetExternalID()
	if id == "" {
		return none, nil
	}
	c, err := d.k.Get(ctx, id, d.marker())
	if clientGone(err) {
		return none, nil
	}
	if err != nil {
		return none, err
	}
	// Scopes are exact: Matches compares the client's default client scopes
	// with the spec's, so a realm default that was added is drift.
	return lifecycle.Observation[clientState]{
		Exists: true, UpToDate: wantErr == nil && c.Matches(d.spec(w)), Current: clientState{kc: c},
	}, nil
}

// secretData is the binding of the client with its current secret (none for a
// public client).
func (d *keycloakDriver) secretData(ctx context.Context, w clientSpec, id string) (binding.Data, error) {
	secret := ""
	if !w.public {
		var err error
		if secret, err = d.k.Secret(ctx, id); err != nil {
			return nil, err
		}
	}
	return d.data(d.claim.GetExternalName(), secret), nil
}

func (d *keycloakDriver) create(ctx context.Context, w clientSpec) (binding.Data, error) {
	c, err := d.k.Create(ctx, d.spec(w))
	if err != nil {
		return nil, err
	}
	// Record the client before anything else can fail.
	d.claim.SetExternalID(c.ID)
	if err := d.persist(ctx); err != nil {
		// A client the status does not name would be found by no one at deletion:
		// take it back (a retry makes it again).
		_ = d.k.Delete(ctx, c.ID)
		d.claim.SetExternalID("")
		return nil, err
	}
	return d.secretData(ctx, w, c.ID)
}

func (d *keycloakDriver) update(ctx context.Context, w clientSpec, cur clientState) (binding.Data, error) {
	if err := d.k.Update(ctx, cur.kc.ID, d.spec(w)); err != nil {
		return nil, err
	}
	d.claim.SetExternalID(cur.kc.ID)
	return d.secretData(ctx, w, cur.kc.ID)
}

func (d *keycloakDriver) delete(ctx context.Context, cur clientState) error {
	return d.k.Delete(ctx, cur.kc.ID)
}

// rotateBegin issues a new secret and keeps the previous one valid when the
// realm's client policy lets Keycloak. The secret the binding Secret holds goes
// with the call, so a retry after a crash adopts the first attempt's secret
// instead of rotating again. A public client has no secret: nothing rotates, and
// the binding is written again as it is.
func (d *keycloakDriver) rotateBegin(ctx context.Context, w clientSpec, _ clientState) (binding.Data, error) {
	id := d.claim.GetExternalID()
	if w.public {
		return d.secretData(ctx, w, id)
	}
	current, err := d.currentSecret(ctx)
	if err != nil {
		return nil, err
	}
	rot, err := d.k.Rotate(ctx, id, current)
	if err != nil {
		return nil, err
	}
	d.noOverlap = !rot.Overlap
	return d.data(d.claim.GetExternalName(), rot.Secret), nil
}

func (d *keycloakDriver) rotateFinish(ctx context.Context) error {
	return d.k.FinishRotation(ctx, d.claim.GetExternalID())
}

func (d *keycloakDriver) hardCut() bool { return d.noOverlap }

// dcrAPI is the part of *idpclient.DCR the driver uses; tests replace it.
type dcrAPI interface {
	Register(ctx context.Context, reg idpclient.Registration) (idpclient.Info, error)
	Get(ctx context.Context, st dcr.State) (idpclient.Info, error)
	Update(ctx context.Context, st dcr.State, reg idpclient.Registration) (idpclient.Info, error)
	Delete(ctx context.Context, st dcr.State) error
}

// dcrDriver manages a client registered with RFC 7591 and 7592. The
// registration (client_id, management URI and registration access token) is a
// Secret in the operator namespace (dcr.Store), written again after every call
// that returns it, since the provider may issue a new token with any answer.
// status.externalId is the client_id the provider assigned; Observe goes by the
// stored registration, never by name. The token goes only to the registration
// endpoint's own origin (idpclient checks the management URI against it).
type dcrDriver struct {
	base
	d     dcrAPI
	store dcr.Store
}

var _ driver = (*dcrDriver)(nil)

// registration is the client metadata as the claim wants it.
func (d *dcrDriver) registration(w clientSpec) idpclient.Registration {
	return idpclient.Registration{
		ClientName: d.claim.GetExternalName(), RedirectURIs: w.redirectURIs, PostLogoutRedirectURIs: w.postLogout,
		GrantTypes: w.grants, TokenEndpointAuthMethod: w.method, Scopes: w.scopes,
	}
}

// save stores the registration the provider answered with when it differs from
// the one held.
func (d *dcrDriver) save(ctx context.Context, held, got dcr.State) error {
	if got == held {
		return nil
	}
	return d.store.Write(ctx, d.claim, got)
}

// record notes the registration in the status.
func (d *dcrDriver) record(st dcr.State) {
	d.claim.SetExternalID(st.ClientID)
	d.claim.Status.RegistrationClientURI = st.RegistrationClientURI
}

func (d *dcrDriver) observe(ctx context.Context, w clientSpec, wantErr error) (lifecycle.Observation[clientState], error) {
	none := lifecycle.Observation[clientState]{}
	// A claim that is being deleted has nothing left to look after once the
	// provider no longer honours its registration: its state goes, and its
	// finalizer is not held for a client nobody can manage.
	deleting := !d.claim.DeletionTimestamp.IsZero()
	st, err := d.store.Read(ctx, d.claim)
	if errors.Is(err, dcr.ErrNotFound) {
		if d.claim.GetExternalID() != "" && !deleting {
			// The operator never registers again by itself: that would change the
			// client_id its workload was given.
			return none, errLost()
		}
		return none, nil
	}
	if err != nil {
		return none, err
	}
	info, err := d.d.Get(ctx, st)
	if errors.Is(err, idpclient.ErrRegistrationLost) && deleting {
		return none, d.store.Delete(ctx, d.claim)
	}
	if err != nil {
		return none, err
	}
	if err := d.save(ctx, st, info.State); err != nil {
		return none, err
	}
	d.record(info.State)
	return lifecycle.Observation[clientState]{
		Exists: true, UpToDate: wantErr == nil && info.Registration.Satisfies(d.registration(w)), Current: clientState{reg: info.State},
	}, nil
}

// register registers a new client and stores its registration before anything
// else. A provider that answers a registration with a document the operator
// cannot use may still have made the client: that is an orphan risk, recorded
// in a condition. A registration whose state cannot be stored is withdrawn. The
// caller writes the status next (persist), because it knows how to take the
// registration back, or what to leave, when that fails.
func (d *dcrDriver) register(ctx context.Context, w clientSpec) (idpclient.Info, error) {
	info, err := d.d.Register(ctx, d.registration(w))
	if err != nil {
		if errors.Is(err, idpclient.ErrBadResponse) {
			d.orphanRisk()
		}
		return info, err
	}
	d.clearOrphanRisk()
	if w.public {
		info.Secret = ""
	}
	if err := d.store.Write(ctx, d.claim, info.State); err != nil {
		if d.d.Delete(ctx, info.State) != nil {
			d.orphanRisk()
		}
		return info, err
	}
	d.record(info.State)
	return info, nil
}

// withdraw takes back a registration the status could not record, and its
// state, so a claim deleted afterwards leaves nothing behind. A registration
// that cannot be deleted is an orphan risk.
func (d *dcrDriver) withdraw(ctx context.Context, st dcr.State) {
	if err := d.d.Delete(ctx, st); err != nil && !errors.Is(err, idpclient.ErrRegistrationLost) {
		d.orphanRisk()
		return
	}
	_ = d.store.Delete(ctx, d.claim)
	d.claim.SetExternalID("")
	d.claim.Status.RegistrationClientURI = ""
}

func (d *dcrDriver) create(ctx context.Context, w clientSpec) (binding.Data, error) {
	info, err := d.register(ctx, w)
	if err != nil {
		return nil, err
	}
	if err := d.persist(ctx); err != nil {
		d.withdraw(ctx, info.State)
		return nil, err
	}
	return d.data(info.State.ClientID, info.Secret), nil
}

func (d *dcrDriver) update(ctx context.Context, w clientSpec, cur clientState) (binding.Data, error) {
	info, err := d.d.Update(ctx, cur.reg, d.registration(w))
	if err != nil {
		return nil, err
	}
	if err := d.store.Write(ctx, d.claim, info.State); err != nil {
		return nil, err
	}
	d.record(info.State)
	secret := info.Secret
	if w.public {
		secret = ""
	} else if secret == "" {
		// The provider returns the secret only when it issues one.
		if secret, err = d.currentSecret(ctx); err != nil {
			return nil, err
		}
		if secret == "" {
			return nil, ErrBindingNotUsable
		}
	}
	return d.data(info.State.ClientID, secret), nil
}

func (d *dcrDriver) delete(ctx context.Context, cur clientState) error {
	// A registration the provider no longer honours is deleted as far as the
	// operator can tell; the stored state goes either way.
	if err := d.d.Delete(ctx, cur.reg); err != nil && !errors.Is(err, idpclient.ErrRegistrationLost) {
		return err
	}
	return d.store.Delete(ctx, d.claim)
}

// rotateBegin re-registers the client: RFC 7591 and 7592 have no way to issue a
// new secret, so the client_id changes and the old registration is deleted, with
// no overlap. A public client has no secret to rotate: the binding is written
// again from the stored registration.
func (d *dcrDriver) rotateBegin(ctx context.Context, w clientSpec, cur clientState) (binding.Data, error) {
	if w.public {
		return d.data(cur.reg.ClientID, ""), nil
	}
	info, err := d.register(ctx, w)
	if err != nil {
		return nil, err
	}
	if err := d.persist(ctx); err != nil {
		// The new registration is stored and the old one is not deleted: the old
		// one stays at the provider, with no token the operator still holds.
		d.orphanRisk()
		return nil, err
	}
	// The new registration is stored and recorded. The old one must not outlive
	// it; if it cannot be deleted its token is gone, so say it may remain.
	if err := d.d.Delete(ctx, cur.reg); err != nil && !errors.Is(err, idpclient.ErrRegistrationLost) {
		d.orphanRisk()
	}
	return d.data(info.State.ClientID, info.Secret), nil
}

func (d *dcrDriver) rotateFinish(context.Context) error { return nil }

func (d *dcrDriver) hardCut() bool { return true }
