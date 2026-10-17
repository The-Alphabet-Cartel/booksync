package multiuser

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/api/audiobookshelf"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
)

// Booksync F2 tests: matching a member to their Audiobookshelf user, the
// admin approval, and the sync gate.

type fakeABSUsers struct {
	users []audiobookshelf.UserSummary
	err   error
	calls int
}

func (f *fakeABSUsers) ListUsers(context.Context) ([]audiobookshelf.UserSummary, error) {
	f.calls++
	return f.users, f.err
}

func absUser(id, username string) audiobookshelf.UserSummary {
	return audiobookshelf.UserSummary{ID: id, Username: username, HasOpenIDLink: true, IsActive: true}
}

func TestMatchABSUser(t *testing.T) {
	inactive := absUser("u-inactive", "carol")
	inactive.IsActive = false
	local := absUser("u-local", "dave")
	local.HasOpenIDLink = false
	users := []audiobookshelf.UserSummary{
		absUser("u-alice", "Alice"),
		absUser("u-bob-1", "bob"),
		absUser("u-bob-2", "BOB"),
		inactive,
		local,
	}

	for _, test := range []struct {
		name     string
		username string
		wantID   string
		wantErr  error
	}{
		{name: "exact match ignoring case", username: "alice", wantID: "u-alice"},
		{name: "surrounding whitespace", username: "  ALICE ", wantID: "u-alice"},
		{name: "no such user", username: "zed", wantErr: ErrABSUserNotFound},
		{name: "empty username", username: "  ", wantErr: ErrABSUserNotFound},
		{name: "two users share the name", username: "bob", wantErr: ErrABSUserAmbiguous},
		{name: "inactive user is skipped", username: "carol", wantErr: ErrABSUserNotFound},
		{name: "user with no OIDC link is skipped", username: "dave", wantErr: ErrABSUserNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := matchABSUser(users, test.username)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantID, got.ID)
		})
	}
}

func newABSLinkService(t *testing.T, users ...audiobookshelf.UserSummary) (*MultiUserService, *fakeABSUsers) {
	t.Helper()
	service, _ := newStatusLookupService(t)
	fake := &fakeABSUsers{users: users}
	service.SetABSUserLister(fake)
	t.Cleanup(func() { require.NoError(t, service.Shutdown(context.Background())) })
	return service, fake
}

func createOwnedProfile(t *testing.T, service *MultiUserService, profileID, ownerID string) {
	t.Helper()
	require.NoError(t, service.repository.CreateProfileForUser(
		profileID, profileID, "http://127.0.0.1:1", "abs-token", "hc-token",
		database.SyncConfigData{DryRun: true}, ownerID,
	))
}

func TestLinkABSUserGoesPendingAndSyncWaitsForApproval(t *testing.T) {
	service, _ := newABSLinkService(t, absUser("abs-alice", "alice"))
	createOwnedProfile(t, service, "alice-profile", "owner-alice")

	// A fresh owned profile has no link and must not sync.
	_, err := service.StartSyncWithAcceptedRun("alice-profile")
	require.ErrorIs(t, err, ErrProfileNotApproved)

	link, err := service.LinkABSUser(context.Background(), "alice-profile", "owner-alice", "Alice")
	require.NoError(t, err)
	require.Equal(t, &ABSLink{State: database.ABSLinkStatePending, ABSUsername: "alice"}, link)

	// Pending is still not approved.
	_, err = service.StartSyncWithAcceptedRun("alice-profile")
	require.ErrorIs(t, err, ErrProfileNotApproved)
	require.False(t, isProfileSyncing(service, "alice-profile"))

	require.NoError(t, service.ApproveABSLink("alice-profile"))
	link, err = service.GetABSLink("alice-profile")
	require.NoError(t, err)
	require.Equal(t, database.ABSLinkStateApproved, link.State)

	// Approved: the gate lets it through (the sync itself then fails fast
	// against the unreachable test URL, which is not what is tested here).
	_, err = service.StartSyncWithAcceptedRun("alice-profile")
	require.False(t, errors.Is(err, ErrProfileNotApproved), "approved profile was refused: %v", err)
	waitForSyncs(service)
}

func TestOwnerlessProfilesAreNotGated(t *testing.T) {
	service, _ := newABSLinkService(t)
	require.NoError(t, service.repository.CreateProfile(
		"legacy", "Legacy", "http://127.0.0.1:1", "abs-token", "hc-token", database.SyncConfigData{DryRun: true},
	))
	_, err := service.StartSyncWithAcceptedRun("legacy")
	require.False(t, errors.Is(err, ErrProfileNotApproved), "ownerless profile was gated: %v", err)
	waitForSyncs(service)
}

func TestLinkABSUserRefusals(t *testing.T) {
	service, fake := newABSLinkService(t, absUser("abs-alice", "alice"), absUser("abs-bob-1", "bob"), absUser("abs-bob-2", "Bob"))
	createOwnedProfile(t, service, "alice-profile", "owner-alice")
	createOwnedProfile(t, service, "bob-profile", "owner-bob")

	_, err := service.LinkABSUser(context.Background(), "alice-profile", "someone-else", "alice")
	require.ErrorIs(t, err, ErrABSLinkNotOwner)
	require.Zero(t, fake.calls, "a non-owner must not trigger an Audiobookshelf lookup")

	_, err = service.LinkABSUser(context.Background(), "bob-profile", "owner-bob", "bob")
	require.ErrorIs(t, err, ErrABSUserAmbiguous)

	_, err = service.LinkABSUser(context.Background(), "alice-profile", "owner-alice", "nobody")
	require.ErrorIs(t, err, ErrABSUserNotFound)

	_, err = service.LinkABSUser(context.Background(), "missing", "owner-alice", "alice")
	require.ErrorIs(t, err, ErrProfileNotFound)

	fake.err = errors.New("connection refused")
	_, err = service.LinkABSUser(context.Background(), "alice-profile", "owner-alice", "alice")
	require.Error(t, err)

	for _, id := range []string{"alice-profile", "bob-profile"} {
		link, err := service.GetABSLink(id)
		require.NoError(t, err)
		require.Equal(t, database.ABSLinkStateNone, link.State, "profile %s", id)
	}
}

func TestLinkABSUserIsIdempotentOncePending(t *testing.T) {
	service, fake := newABSLinkService(t, absUser("abs-alice", "alice"))
	createOwnedProfile(t, service, "alice-profile", "owner-alice")

	_, err := service.LinkABSUser(context.Background(), "alice-profile", "owner-alice", "alice")
	require.NoError(t, err)
	link, err := service.LinkABSUser(context.Background(), "alice-profile", "owner-alice", "alice")
	require.NoError(t, err)
	require.Equal(t, database.ABSLinkStatePending, link.State)
	require.Equal(t, 1, fake.calls, "a pending link must not be matched again")
}

func TestOneABSUserCannotBeHeldByTwoProfiles(t *testing.T) {
	service, _ := newABSLinkService(t, absUser("abs-alice", "alice"))
	createOwnedProfile(t, service, "first", "owner-alice")
	createOwnedProfile(t, service, "second", "owner-mallory")

	_, err := service.LinkABSUser(context.Background(), "first", "owner-alice", "alice")
	require.NoError(t, err)

	// Someone who took "alice" as a Pocket ID username after a rename: refused
	// while the first profile holds the user, even though only pending.
	_, err = service.LinkABSUser(context.Background(), "second", "owner-mallory", "alice")
	require.ErrorIs(t, err, database.ErrABSUserAlreadyLinked)

	// An admin cannot hand the same user to the second profile either.
	_, err = service.SetABSLinkManually(context.Background(), "second", "abs-alice")
	require.ErrorIs(t, err, database.ErrABSUserAlreadyLinked)
}

func TestRejectFreesTheABSUserAndDeleteReleasesIt(t *testing.T) {
	service, _ := newABSLinkService(t, absUser("abs-alice", "alice"))
	createOwnedProfile(t, service, "first", "owner-alice")
	createOwnedProfile(t, service, "second", "owner-alice")

	_, err := service.LinkABSUser(context.Background(), "first", "owner-alice", "alice")
	require.NoError(t, err)
	require.NoError(t, service.RejectABSLink("first"))
	link, err := service.GetABSLink("first")
	require.NoError(t, err)
	require.Equal(t, &ABSLink{State: database.ABSLinkStateRejected}, link)

	// Rejected cannot be approved.
	require.ErrorIs(t, service.ApproveABSLink("first"), database.ErrABSLinkStateConflict)

	// The user is free again.
	_, err = service.LinkABSUser(context.Background(), "second", "owner-alice", "alice")
	require.NoError(t, err)
	require.NoError(t, service.ApproveABSLink("second"))

	// Deleting the profile releases the user for a new profile.
	require.NoError(t, service.repository.DeleteProfile("second"))
	createOwnedProfile(t, service, "third", "owner-alice")
	_, err = service.LinkABSUser(context.Background(), "third", "owner-alice", "alice")
	require.NoError(t, err)
}

func TestSetABSLinkManuallyApprovesAtOnce(t *testing.T) {
	inactive := absUser("abs-gone", "gone")
	inactive.IsActive = false
	local := absUser("abs-local", "renamed-member")
	local.HasOpenIDLink = false
	service, _ := newABSLinkService(t, local, inactive)
	createOwnedProfile(t, service, "member", "owner-member")

	link, err := service.SetABSLinkManually(context.Background(), "member", "abs-local")
	require.NoError(t, err)
	require.Equal(t, &ABSLink{State: database.ABSLinkStateApproved, ABSUsername: "renamed-member"}, link)

	_, err = service.SetABSLinkManually(context.Background(), "member", "abs-gone")
	require.ErrorIs(t, err, ErrABSUserNotFound)
	_, err = service.SetABSLinkManually(context.Background(), "member", "abs-nonexistent")
	require.ErrorIs(t, err, ErrABSUserNotFound)

	options, err := service.ListABSUserOptions(context.Background())
	require.NoError(t, err)
	require.Equal(t, []ABSUserOption{{ID: "abs-local", Username: "renamed-member", HasOpenIDLink: false}}, options)
}

func TestListABSLinksForAdminView(t *testing.T) {
	service, _ := newABSLinkService(t, absUser("abs-alice", "alice"))
	createOwnedProfile(t, service, "alice-profile", "owner-alice")
	require.NoError(t, service.repository.CreateProfile(
		"legacy", "Legacy", "http://127.0.0.1:1", "abs-token", "hc-token", database.SyncConfigData{},
	))
	_, err := service.LinkABSUser(context.Background(), "alice-profile", "owner-alice", "alice")
	require.NoError(t, err)

	rows, err := service.ListABSLinks()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	byID := map[string]database.ABSLinkRow{}
	for _, row := range rows {
		byID[row.ProfileID] = row
	}
	require.Equal(t, database.ABSLinkStatePending, byID["alice-profile"].ABSLinkState)
	require.Equal(t, "alice", byID["alice-profile"].ABSUsername)
	require.NotNil(t, byID["alice-profile"].ABSUserID)
	require.Equal(t, database.ABSLinkStateNone, byID["legacy"].ABSLinkState)
	require.Nil(t, byID["legacy"].ABSUserID)
}

func TestABSLinkWithoutServerSettingsIsNotConfigured(t *testing.T) {
	service, _ := newStatusLookupService(t)
	createOwnedProfile(t, service, "alice-profile", "owner-alice")
	_, err := service.LinkABSUser(context.Background(), "alice-profile", "owner-alice", "alice")
	require.ErrorIs(t, err, ErrABSNotConfigured)
}
