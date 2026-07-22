package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"
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
