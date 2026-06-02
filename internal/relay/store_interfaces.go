package relay

import (
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
)

// Narrow, consumer-oriented store interfaces. Each groups the methods one
// domain needs, so the Phase-2 service layer can depend on the slice of
// persistence it actually uses and be unit-tested with a fake instead of
// Postgres (mirroring internal/media.Store + its fakes). The concrete
// *Store remains the only production implementation; the assertions below
// keep these in lock-step with it at compile time.

// ClipStore is the clip persistence surface used by the clip service.
type ClipStore interface {
	SaveClip(userID string, req *cinchv1.PushClipRequest) (*cinchv1.Clip, bool, error)
	ListClips(userID string, limit int) ([]*cinchv1.Clip, error)
	ListClipsSince(userID string, since time.Time, limit int) ([]*cinchv1.Clip, error)
	ListClipsFiltered(userID string, f ListFilter) ([]*cinchv1.Clip, error)
	GetLatestClipBySource(userID, source string) (*cinchv1.Clip, error)
	GetLatestClipExcludingSource(userID, excludeSource string) (*cinchv1.Clip, error)
	GetLatestClipForUser(userID string) (*cinchv1.Clip, error)
	DeleteClip(userID, clipID string) error
	DeleteClipReturningMedia(userID, clipID string) (mediaPath string, err error)
	SetClipPin(userID, clipID string, isPinned bool, pinNote *string) error
	GetClipMediaPath(userID, clipID string) (string, error)
	InsertTombstone(userID, clipID string) error
	ListTombstones(userID string, since time.Time, limit int) ([]Tombstone, error)
}

// AuthStore is the user/identity surface used by the auth service.
type AuthStore interface {
	GetAuthContext(token string) (*AuthContext, error)
	UserByToken(token string) (string, error)
	CreateUser(id string) error
	CountUsers() (int, error)
	SetUserAdmin(userID string, admin bool) error
	IsUserAdmin(userID string) (bool, error)
	SetUserDisplayName(userID, name string) error
	UpsertOAuthUser(provider, subject, email string, emailVerified bool, displayName, hostname, machineID string) (string, string, string, error)
	IsDemoUser(userID string) (bool, error)
	GetUserCapabilities(userID string) (UserCapabilities, error)
	GetUserStorageUsage(userID string) (int64, error)
	IncrementDailyRequestCount(userID string) (int, error)
}

// DeviceStore is the device surface used by the device service.
type DeviceStore interface {
	ListDevices(userID string) ([]*cinchv1.Device, error)
	DeviceOwner(deviceID string) (userID string, err error)
	DeviceIDByToken(token string) (deviceID string, revoked bool, err error)
	RevokeDevice(deviceID string) (revokedAt time.Time, err error)
	RegisterDeviceWithToken(userID, deviceID, hostname, token string) error
	SetDeviceNickname(deviceID, nickname string) error
	UpdateDeviceActivity(userID, source string) error
	UpdateDeviceRetention(deviceID string, days int) error
	CountActiveDevices(userID string) (int, error)
	CreateDeviceForUser(userID, hostname, machineID string) (deviceID, token string, err error)
}

// InviteStore is the invite surface used by login + admin invite handlers.
type InviteStore interface {
	CreateInvite(codeHash string, createdBy *string, label string, maxUses int, expiresAt time.Time) error
	RedeemInvite(codeHash string) error
	ListInvites() ([]Invite, error)
	RevokeInvite(codeHash string) error
}

// KeyExchangeStore is the device key-bundle surface used by the key service.
type KeyExchangeStore interface {
	SaveKeyBundle(deviceID, ephPubKeyB64, encryptedBundleB64 string) error
	GetKeyBundle(deviceID string) (ephPubKeyB64, encryptedBundleB64 string, err error)
	GetKeyBundlePendingSince(deviceID string) (time.Time, error)
	SetDevicePublicKey(deviceID, pubKeyB64, fingerprint string) error
	GetDevicePublicKey(deviceID string) (string, error)
	GetDeviceHostnameAndPubKey(deviceID string) (hostname, pubKey string, err error)
	ListPendingKeyExchanges(userID string) ([]*cinchv1.Device, error)
	DeviceOwner(deviceID string) (userID string, err error)
}

// DeviceCodeStore is the device-code flow surface used by the auth service.
type DeviceCodeStore interface {
	CreateDeviceCode(hostname, machineID, userHint, requesterIP string) (*cinchv1.DeviceCodeStartResponse, string, error)
	CompleteDeviceCode(userCode, userID, deviceID, token string) error
	DenyDeviceCode(userCode, userID string) error
	PollDeviceCode(deviceCode string) (*cinchv1.DeviceCodePollResponse, error)
	DeviceCodeContext(userCode string) (string, string, error)
	DeviceCodeHostname(userCode string) (string, error)
	ListPendingDeviceCodes(userID string) ([]PendingDeviceCodeRow, error)
	CreateDeviceForUser(userID, hostname, machineID string) (deviceID, token string, err error)
}

// Compile-time proof that the concrete Postgres store satisfies every narrow
// interface. If a signature drifts, the build breaks here rather than at a
// distant call site.
var (
	_ ClipStore        = (*Store)(nil)
	_ AuthStore        = (*Store)(nil)
	_ DeviceStore      = (*Store)(nil)
	_ InviteStore      = (*Store)(nil)
	_ KeyExchangeStore = (*Store)(nil)
	_ DeviceCodeStore  = (*Store)(nil)
)
