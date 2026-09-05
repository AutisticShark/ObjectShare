package db

import (
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm/schema"
)

func TestFileSharingMigrationMetadata(t *testing.T) {
	parsed, err := schema.Parse(&FileList{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	mode := parsed.FieldsByDBName["share_mode"]
	if mode == nil || !mode.NotNull || mode.DefaultValue != "link" {
		t.Fatalf("legacy files do not retain unlisted access: %#v", mode)
	}
	users := parsed.FieldsByDBName["share_user_ids"]
	if users == nil || !users.NotNull || users.DataType != "jsonb" || users.Serializer == nil || users.DefaultValue != "'[]'" {
		t.Fatalf("invalid recipient storage: %#v", users)
	}
	if _, ok := parsed.ParseCheckConstraints()["chk_file_share_mode"]; !ok {
		t.Fatal("missing database access-mode constraint")
	}
}

func TestFileSharingRejectsInvalidPoliciesBeforeDatabase(t *testing.T) {
	repo := &GormRepository{}
	for _, input := range []struct {
		mode  string
		users []string
	}{
		{"", nil}, {"bad", nil}, {ShareSelected, nil}, {SharePrivate, []string{uuid.NewString()}}, {ShareSelected, []string{"bad-uuid"}}, {ShareSelected, make([]string, MaxShareUsers+1)},
	} {
		if err := repo.SetFileSharing(t.Context(), uuid.NewString(), input.mode, input.users); err == nil {
			t.Fatalf("accepted invalid policy: %+v", input)
		}
	}
}

func TestPostgresFileSharingMigrationAndPersistence(t *testing.T) {
	repo := creditTestRepository(t)
	// Create the former schema first to verify the upgrade preserves an existing
	// UUID link, filename, and ownership capability without overwriting values.
	if err := repo.connection.Exec(`CREATE TABLE file_lists (
 id bigserial PRIMARY KEY, file_id uuid NOT NULL UNIQUE,
 anonymous_session_token varchar(64) NOT NULL, file_name varchar(255) NOT NULL,
 file_size bigint NOT NULL, file_sha256 varchar(64) NOT NULL,
 file_sha3 varchar(64) NOT NULL, storage_service varchar(32) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
 )`).Error; err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	if err := repo.connection.Exec(`INSERT INTO file_lists (file_id,anonymous_session_token,file_name,file_size,file_sha256,file_sha3,storage_service) VALUES (?, 'owner-hash', 'legacy.txt', 6, '', '', 'filesystem')`, id).Error; err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := repo.connection.AutoMigrate(&FileList{}); err != nil {
			t.Fatal(err)
		}
	}
	file, err := repo.Get(t.Context(), id)
	if err != nil || file.ShareMode != ShareLink || len(file.ShareUserIDs) != 0 || file.FileName != "legacy.txt" || file.AnonymousSessionToken != "owner-hash" {
		t.Fatalf("legacy migration: %+v %v", file, err)
	}
	recipient := uuid.NewString()
	if err := repo.SetFileSharing(t.Context(), id, ShareSelected, []string{recipient}); err != nil {
		t.Fatal(err)
	}
	file, err = repo.Get(t.Context(), id)
	if err != nil || file.ShareMode != ShareSelected || len(file.ShareUserIDs) != 1 || file.ShareUserIDs[0] != recipient {
		t.Fatalf("JSON recipient round trip: %+v %v", file, err)
	}
	if err := repo.SetFileSharing(t.Context(), id, SharePrivate, nil); err != nil {
		t.Fatal(err)
	}
	file, err = repo.Get(t.Context(), id)
	if err != nil || file.ShareMode != SharePrivate || len(file.ShareUserIDs) != 0 {
		t.Fatalf("grant revocation: %+v %v", file, err)
	}
	if err := repo.connection.Model(&FileList{}).Where("file_id = ?", id).Update("upload_status", "deleting").Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.SetFileSharing(t.Context(), id, ShareLink, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("modified a deleting file: %v", err)
	}
}
