package store

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	s3LocationXML = `<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`
	// Exactly what S3 and MinIO answer for a bucket created WITHOUT Object Lock.
	s3NoLockXML = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>ObjectLockConfigurationNotFoundError</Code><Message>Object Lock configuration does not exist for this bucket</Message><BucketName>evidence</BucketName></Error>`
	// Exactly what S3 and MinIO answer for a bucket created WITH Object Lock.
	s3LockEnabledXML = `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`
	s3LockUnsetXML   = `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></ObjectLockConfiguration>`
)

// fakeS3 answers the bucket-level calls NewS3Store makes. lockResponse is the
// body (and 200/404 status) returned for GET ?object-lock.
type fakeS3 struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
	hangPut  chan struct{}
}

func newFakeS3(t *testing.T, lockStatus int, lockBody string) *fakeS3 {
	t.Helper()
	f := &fakeS3{hangPut: make(chan struct{})}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.RawQuery)
		f.mu.Unlock()
		switch {
		case r.URL.RawQuery == "location=":
			_, _ = w.Write([]byte(s3LocationXML))
		case r.URL.RawQuery == "object-lock=":
			w.WriteHeader(lockStatus)
			_, _ = w.Write([]byte(lockBody))
		case r.Method == http.MethodPut:
			<-f.hangPut // never answers until the test ends
		default:
			w.WriteHeader(http.StatusOK) // HEAD bucket
		}
	}))
	t.Cleanup(func() { close(f.hangPut); f.Close() })
	return f
}

func (f *fakeS3) config(objectLock bool) S3Config {
	return S3Config{
		Endpoint: strings.TrimPrefix(f.URL, "http://"), Bucket: "evidence",
		AccessKey: "access", SecretKey: "secret", ObjectLock: objectLock, RetentionDays: 2555,
	}
}

func (f *fakeS3) asked(query string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if strings.HasSuffix(r, " "+query) {
			return true
		}
	}
	return false
}

func TestNewS3StoreRefusesBucketWithoutObjectLock(t *testing.T) {
	f := newFakeS3(t, http.StatusNotFound, s3NoLockXML)
	_, err := NewS3Store(context.Background(), f.config(true))
	if err == nil {
		t.Fatal("a Tier-3 store must refuse to boot against a bucket without Object Lock")
	}
	// blindfold: contract — the boot error must say what is wrong and that it cannot be fixed after creation.
	if !strings.Contains(err.Error(), "Object Lock") || !strings.Contains(err.Error(), "created with Object Lock enabled") {
		t.Fatalf("error must explain the Object Lock requirement, got: %v", err)
	}
}

func TestNewS3StoreRefusesLockConfigThatIsNotEnabled(t *testing.T) {
	f := newFakeS3(t, http.StatusOK, s3LockUnsetXML)
	if _, err := NewS3Store(context.Background(), f.config(true)); err == nil {
		t.Fatal("an Object Lock configuration without status Enabled must be refused")
	}
}

func TestNewS3StoreAcceptsBucketWithObjectLock(t *testing.T) {
	f := newFakeS3(t, http.StatusOK, s3LockEnabledXML)
	if _, err := NewS3Store(context.Background(), f.config(true)); err != nil {
		t.Fatalf("a bucket with Object Lock enabled must be accepted: %v", err)
	}
}

func TestNewS3StoreSkipsLockCheckWhenWORMNotRequested(t *testing.T) {
	f := newFakeS3(t, http.StatusNotFound, s3NoLockXML)
	if _, err := NewS3Store(context.Background(), f.config(false)); err != nil {
		t.Fatalf("Tier 2 (no Object Lock requested) must boot on any existing bucket: %v", err)
	}
	if f.asked("object-lock=") {
		t.Fatal("Tier 2 must not query Object Lock configuration")
	}
}

func TestS3OperationTimeoutBoundsAHungBackend(t *testing.T) {
	f := newFakeS3(t, http.StatusOK, s3LockEnabledXML)
	cfg := f.config(false)
	cfg.OpTimeout = 300 * time.Millisecond
	s, err := NewS3Store(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- s.Put("sha256:"+strings.Repeat("a", 64), "jwt") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a Put to an unresponsive backend must fail")
		}
		// blindfold: contract — S3Config.OpTimeout bounds every request; allow generous scheduling slack.
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("Put must give up near OpTimeout (300ms), took %v", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Put to an unresponsive backend is still blocked after 3s: OpTimeout is not enforced")
	}
}
