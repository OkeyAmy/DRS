package store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config configures an S3-compatible durable backend.
type S3Config struct {
	Endpoint      string
	Bucket        string
	AccessKey     string
	SecretKey     string
	Region        string
	UseSSL        bool
	ObjectLock    bool
	RetentionDays int64
	// OpTimeout bounds every S3 request (the Store interface carries no
	// context); 0 -> 30s.
	OpTimeout time.Duration
}

const defaultS3OpTimeout = 30 * time.Second

// s3ClientMaxRetries caps the S3 client library's own per-request retries
// (default 10, with backoff). AsyncStore already retries with backoff and
// redrives failed writes, so a long inner retry only delays the failure signal:
// measured against a dead endpoint, the default made each receipt take ~15-20 s
// to be reported as failed.
const s3ClientMaxRetries = 2

// S3Store is a durable Store backed by any S3-compatible object store. When
// ObjectLock is set, every Put applies a COMPLIANCE-mode retain-until date,
// making stored evidence immutable and undeletable until the retention window
// elapses (WORM). The bucket MUST have object locking enabled at creation for
// this to take effect.
type S3Store struct {
	client        *minio.Client
	bucket        string
	objectLock    bool
	retentionDays int64
	opTimeout     time.Duration
}

// NewS3Store connects to the endpoint and verifies the bucket exists. When
// cfg.ObjectLock is set it also verifies the bucket really has Object Lock
// enabled, so a misconfigured bucket fails at boot instead of silently losing
// evidence at the first background write.
func NewS3Store(ctx context.Context, cfg S3Config) (*S3Store, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:      credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure:     cfg.UseSSL,
		Region:     cfg.Region,
		MaxRetries: s3ClientMaxRetries,
	})
	if err != nil {
		return nil, fmt.Errorf("store: s3 client: %w", err)
	}
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("store: s3 bucket check: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("store: s3 bucket %q does not exist (create it with object-lock enabled for Tier 3)", cfg.Bucket)
	}
	if cfg.ObjectLock {
		if err := verifyObjectLock(ctx, client, cfg.Bucket); err != nil {
			return nil, err
		}
	}
	timeout := cfg.OpTimeout
	if timeout <= 0 {
		timeout = defaultS3OpTimeout
	}
	return &S3Store{
		client:        client,
		bucket:        cfg.Bucket,
		objectLock:    cfg.ObjectLock,
		retentionDays: cfg.RetentionDays,
		opTimeout:     timeout,
	}, nil
}

// verifyObjectLock fails unless the bucket has Object Lock enabled. Object Lock
// can only be turned on when a bucket is created, so there is no way to repair
// a bucket at runtime — refusing to start is the only safe answer.
func verifyObjectLock(ctx context.Context, client *minio.Client, bucket string) error {
	status, _, _, _, err := client.GetObjectLockConfig(ctx, bucket)
	if err != nil {
		return fmt.Errorf("store: s3 bucket %q does not report an Object Lock configuration "+
			"(it must be created with Object Lock enabled): %w", bucket, err)
	}
	if status != "Enabled" {
		return fmt.Errorf("store: s3 bucket %q has Object Lock status %q, want \"Enabled\"", bucket, status)
	}
	return nil
}

// opCtx returns a context that bounds one S3 request.
func (s *S3Store) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.opTimeout)
}

// objectName maps a store key to an object name. Keys are "sha256:"+hex with an
// optional ".jwt"/".tst" suffix; we shard by the first 4 hex chars to avoid hot
// prefixes, mirroring the filesystem layout.
func objectName(hash string) (string, error) {
	name := strings.TrimPrefix(hash, "sha256:")
	m := validKeyRe.FindStringSubmatch(name)
	if m == nil {
		return "", fmt.Errorf("store: invalid key %q", hash)
	}
	digest, ext := m[1], m[2]
	if ext == "" {
		ext = "jwt"
	}
	return fmt.Sprintf("%s/%s.%s", digest[:4], digest, ext), nil
}

// Put stores a JWT under its chain hash key. When ObjectLock is enabled the
// object is written with COMPLIANCE mode retention, making it WORM-protected
// until the retention window elapses.
func (s *S3Store) Put(hash, jwt string) error {
	name, err := objectName(hash)
	if err != nil {
		return err
	}
	opts := minio.PutObjectOptions{ContentType: "application/jwt"}
	if s.objectLock {
		opts.Mode = minio.Compliance
		opts.RetainUntilDate = time.Now().UTC().AddDate(0, 0, int(s.retentionDays))
	}
	ctx, cancel := s.opCtx()
	defer cancel()
	_, err = s.client.PutObject(ctx, s.bucket, name,
		strings.NewReader(jwt), int64(len(jwt)), opts)
	if err != nil {
		return fmt.Errorf("store: s3 put: %w", err)
	}
	return nil
}

// Get retrieves a JWT by its chain hash key. Returns ErrNotFound if the object
// does not exist. Other read failures (network, auth, corruption) return a
// wrapped error so the caller can distinguish missing evidence from an access
// fault — a silent fail-open on unexpected errors is a security violation.
func (s *S3Store) Get(hash string) (string, error) {
	name, err := objectName(hash)
	if err != nil {
		return "", err
	}
	ctx, cancel := s.opCtx()
	defer cancel()
	obj, err := s.client.GetObject(ctx, s.bucket, name, minio.GetObjectOptions{})
	if err != nil {
		return "", fmt.Errorf("store: s3 get: %w", err)
	}
	defer obj.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, obj); err != nil {
		// GetObject is lazy: the 404 surfaces here during the first read.
		if minio.ToErrorResponse(err).Code == minio.NoSuchKey {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("store: s3 get: %w", err)
	}
	return buf.String(), nil
}

// Delete removes a JWT entry. Under Object Lock (WORM) this is a logged no-op:
// a simple RemoveObject on a versioned, Object-Lock bucket writes a delete
// marker rather than removing the retained version, hiding evidence without
// destroying it. Deletion of compliance evidence is governed by the bucket's
// Object Lock retention/lifecycle policy, not this API.
func (s *S3Store) Delete(hash string) error {
	name, err := objectName(hash)
	if err != nil {
		return err
	}
	if s.objectLock {
		// WORM/compliance: objects are immutable until their Object Lock
		// retention expires. A simple S3 delete would only add a delete marker
		// (hiding the current version) without removing the retained evidence,
		// which is misleading. Deletion of compliance evidence is governed by
		// the bucket's Object Lock retention/lifecycle policy, not this API.
		slog.Warn("s3 store: Delete ignored — Object Lock (WORM) store; evidence is immutable until retention expires", "key", hash)
		return nil
	}
	ctx, cancel := s.opCtx()
	defer cancel()
	if err := s.client.RemoveObject(ctx, s.bucket, name, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("store: s3 delete: %w", err)
	}
	return nil
}

// objectRetention returns the Object Lock retention (mode + retain-until) for
// the current version of the object under hash. Used to verify WORM was applied.
func (s *S3Store) objectRetention(ctx context.Context, hash string) (*minio.RetentionMode, *time.Time, error) {
	name, err := objectName(hash)
	if err != nil {
		return nil, nil, err
	}
	return s.client.GetObjectRetention(ctx, s.bucket, name, "")
}
