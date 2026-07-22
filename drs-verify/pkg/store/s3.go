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
}

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
}

// NewS3Store connects to the endpoint and verifies the bucket exists.
func NewS3Store(ctx context.Context, cfg S3Config) (*S3Store, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
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
	return &S3Store{
		client:        client,
		bucket:        cfg.Bucket,
		objectLock:    cfg.ObjectLock,
		retentionDays: cfg.RetentionDays,
	}, nil
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
	_, err = s.client.PutObject(context.Background(), s.bucket, name,
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
	obj, err := s.client.GetObject(context.Background(), s.bucket, name, minio.GetObjectOptions{})
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
	if err := s.client.RemoveObject(context.Background(), s.bucket, name, minio.RemoveObjectOptions{}); err != nil {
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
