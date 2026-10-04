package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestS3Store_PutGetDeleteRoundTrip requires a MinIO/S3 endpoint. Run locally with:
//
//	docker run -p 9000:9000 -e MINIO_ROOT_USER=minioadmin \
//	  -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data
//	S3_TEST_ENDPOINT=localhost:9000 S3_TEST_ACCESS=minioadmin \
//	  S3_TEST_SECRET=minioadmin go test ./pkg/store/ -run S3
//
// Skipped when S3_TEST_ENDPOINT is unset — this is an integration test and
// must exercise real Put/Get/Delete against a live endpoint, not a mock.
func s3TestConfig(t *testing.T) S3Config {
	t.Helper()
	ep := os.Getenv("S3_TEST_ENDPOINT")
	if ep == "" {
		t.Skip("S3_TEST_ENDPOINT not set — skipping S3 integration test")
	}
	return S3Config{
		Endpoint:  ep,
		Bucket:    "drs-store-test",
		AccessKey: os.Getenv("S3_TEST_ACCESS"),
		SecretKey: os.Getenv("S3_TEST_SECRET"),
		Region:    "us-east-1",
		UseSSL:    false,
	}
}

func TestS3Store_PutGetDeleteRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := NewS3Store(ctx, s3TestConfig(t))
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	// Derive a unique 64-char lowercase hex key from the current timestamp so
	// the key satisfies validKeyRe (^[0-9a-f]{64}$) and avoids collisions
	// between concurrent test runs.
	sum := sha256.Sum256([]byte(time.Now().String()))
	key := "sha256:" + hex.EncodeToString(sum[:])

	const jwtBody = "jwt-body"
	if err := s.Put(key, jwtBody); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// blindfold: invariant — Get must return exactly what Put stored; S3 must not mutate object contents
	if got != jwtBody {
		t.Fatalf("round-trip: got %q want %q", got, jwtBody)
	}
	if err := s.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(key); err != ErrNotFound {
		t.Fatalf("after delete: got %v want ErrNotFound", err)
	}
}

// hexOf returns the hex-encoded SHA-256 digest of s — a 64-char lowercase
// string that satisfies validKeyRe (^[0-9a-f]{64}$).
func hexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestS3Store_ObjectLock_RetentionApplied proves WORM semantics via
// GetObjectRetention rather than delete-then-get. The delete-then-get pattern
// is unreliable on Object Lock buckets: RemoveObject writes a delete marker
// (Get returns NoSuchKey) while the retained version remains immutable.
//
// Requires a bucket created WITH object lock enabled:
//
//	mc mb --with-lock <alias>/drs-worm-test
//
// Skipped when S3_TEST_ENDPOINT is unset.
func TestS3Store_ObjectLock_RetentionApplied(t *testing.T) {
	ep := os.Getenv("S3_TEST_ENDPOINT")
	if ep == "" {
		t.Skip("S3_TEST_ENDPOINT not set")
	}
	ctx := context.Background()
	cfg := S3Config{
		Endpoint:      ep,
		Bucket:        "drs-worm-test",
		AccessKey:     os.Getenv("S3_TEST_ACCESS"),
		SecretKey:     os.Getenv("S3_TEST_SECRET"),
		Region:        "us-east-1",
		UseSSL:        false,
		ObjectLock:    true,
		RetentionDays: 3650,
	}
	s, err := NewS3Store(ctx, cfg)
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	// Unique valid 64-hex key per run.
	key := "sha256:" + hexOf(time.Now().String())
	if err := s.Put(key, "compliance-evidence"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// WORM proof: the object carries a COMPLIANCE retention ending ~RetentionDays
	// out. Deterministic, unlike delete-then-get (confounded by delete markers).
	mode, until, err := s.objectRetention(ctx, key)
	if err != nil {
		t.Fatalf("objectRetention: %v", err)
	}
	// blindfold: invariant — Put with ObjectLock=true must set COMPLIANCE mode;
	// any other mode (GOVERNANCE, nil) means retention was not applied correctly.
	if mode == nil || *mode != minio.Compliance {
		t.Fatalf("retention mode = %v, want COMPLIANCE", mode)
	}
	// blindfold: invariant — retain-until must be ~3650 days out;
	// minUntil is 3600 days out to give generous slack for clock skew.
	minUntil := time.Now().Add(3600 * 24 * time.Hour)
	if until == nil || until.Before(minUntil) {
		t.Fatalf("retain-until = %v, want ~3650 days out", until)
	}
}

// TestS3Store_BootChecksObjectLockOnRealServer proves the Tier-3 boot rule
// against a real S3-compatible server: a bucket created with Object Lock is
// accepted, one created without it is refused. Creates and removes its own
// buckets. Skipped when S3_TEST_ENDPOINT is unset.
func TestS3Store_BootChecksObjectLockOnRealServer(t *testing.T) {
	ep := os.Getenv("S3_TEST_ENDPOINT")
	if ep == "" {
		t.Skip("S3_TEST_ENDPOINT not set")
	}
	ctx := context.Background()
	admin, err := minio.New(ep, &minio.Options{
		Creds: credentials.NewStaticV4(os.Getenv("S3_TEST_ACCESS"), os.Getenv("S3_TEST_SECRET"), ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	suffix := hexOf(time.Now().String())[:12]
	locked, plain := "drs-lock-"+suffix, "drs-plain-"+suffix
	if err := admin.MakeBucket(ctx, locked, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
		t.Fatalf("create locked bucket: %v", err)
	}
	if err := admin.MakeBucket(ctx, plain, minio.MakeBucketOptions{}); err != nil {
		t.Fatalf("create plain bucket: %v", err)
	}
	t.Cleanup(func() { _ = admin.RemoveBucket(ctx, locked); _ = admin.RemoveBucket(ctx, plain) })

	cfg := func(bucket string) S3Config {
		return S3Config{Endpoint: ep, Bucket: bucket, AccessKey: os.Getenv("S3_TEST_ACCESS"),
			SecretKey: os.Getenv("S3_TEST_SECRET"), ObjectLock: true, RetentionDays: 1}
	}
	if _, err := NewS3Store(ctx, cfg(locked)); err != nil {
		t.Fatalf("a bucket created with Object Lock must be accepted: %v", err)
	}
	// blindfold: contract — Object Lock cannot be enabled after creation, so a plain bucket must be refused at boot.
	if _, err := NewS3Store(ctx, cfg(plain)); err == nil {
		t.Fatal("a bucket created without Object Lock must be refused when ObjectLock is requested")
	}
}
