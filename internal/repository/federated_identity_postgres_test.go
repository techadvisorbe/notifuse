package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Notifuse/notifuse/internal/domain"
	"github.com/Notifuse/notifuse/internal/repository/testutil"
)

func TestFederatedIdentityRepository_GetByIssuerSubject(t *testing.T) {
	db, mock, cleanup := testutil.SetupMockDB(t)
	defer cleanup()
	repo := NewFederatedIdentityRepository(db)

	t.Run("found", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "user_id", "idp_issuer", "idp_sub", "created_at"}).
			AddRow("fi-1", "user-1", "https://idp.example.com", "sub-123", time.Now().UTC())
		mock.ExpectQuery(`SELECT id, user_id, idp_issuer, idp_sub, created_at FROM federated_identities WHERE idp_issuer=\$1 AND idp_sub=\$2`).
			WithArgs("https://idp.example.com", "sub-123").
			WillReturnRows(rows)

		fi, err := repo.GetByIssuerSubject(context.Background(), "https://idp.example.com", "sub-123")
		require.NoError(t, err)
		assert.Equal(t, "user-1", fi.UserID)
		assert.Equal(t, "sub-123", fi.IDPSub)
	})

	t.Run("not found maps to typed error", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id, user_id, idp_issuer, idp_sub, created_at FROM federated_identities WHERE idp_issuer=\$1 AND idp_sub=\$2`).
			WithArgs("https://idp.example.com", "missing").
			WillReturnError(sql.ErrNoRows)

		_, err := repo.GetByIssuerSubject(context.Background(), "https://idp.example.com", "missing")
		var notFound *domain.ErrFederatedIdentityNotFound
		assert.True(t, errors.As(err, &notFound), "expected *ErrFederatedIdentityNotFound, got %v", err)
	})
}

func TestFederatedIdentityRepository_GetByUserAndIssuer(t *testing.T) {
	db, mock, cleanup := testutil.SetupMockDB(t)
	defer cleanup()
	repo := NewFederatedIdentityRepository(db)

	rows := sqlmock.NewRows([]string{"id", "user_id", "idp_issuer", "idp_sub", "created_at"}).
		AddRow("fi-1", "user-1", "https://idp.example.com", "sub-123", time.Now().UTC())
	mock.ExpectQuery(`SELECT id, user_id, idp_issuer, idp_sub, created_at FROM federated_identities WHERE user_id=\$1 AND idp_issuer=\$2`).
		WithArgs("user-1", "https://idp.example.com").
		WillReturnRows(rows)

	fi, err := repo.GetByUserAndIssuer(context.Background(), "user-1", "https://idp.example.com")
	require.NoError(t, err)
	assert.Equal(t, "sub-123", fi.IDPSub)
}

func TestFederatedIdentityRepository_Create(t *testing.T) {
	db, mock, cleanup := testutil.SetupMockDB(t)
	defer cleanup()
	repo := NewFederatedIdentityRepository(db)

	t.Run("success auto-fills id", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO federated_identities \(id, user_id, idp_issuer, idp_sub, created_at\) VALUES \(\$1, \$2, \$3, \$4, \$5\)`).
			WithArgs(sqlmock.AnyArg(), "user-1", "https://idp.example.com", "sub-123", sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		fi := &domain.FederatedIdentity{UserID: "user-1", IDPIssuer: "https://idp.example.com", IDPSub: "sub-123"}
		err := repo.Create(context.Background(), fi)
		require.NoError(t, err)
		assert.NotEmpty(t, fi.ID, "Create should auto-fill the id")
	})

	t.Run("unique violation maps to ErrFederatedIdentityExists", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO federated_identities`).
			WithArgs(sqlmock.AnyArg(), "user-1", "https://idp.example.com", "sub-999", sqlmock.AnyArg()).
			WillReturnError(errors.New("pq: duplicate key value violates unique constraint \"federated_identities_user_id_idp_issuer_key\""))

		fi := &domain.FederatedIdentity{UserID: "user-1", IDPIssuer: "https://idp.example.com", IDPSub: "sub-999"}
		err := repo.Create(context.Background(), fi)
		var exists *domain.ErrFederatedIdentityExists
		assert.True(t, errors.As(err, &exists), "expected *ErrFederatedIdentityExists, got %v", err)
	})
}

func TestFederatedIdentityRepository_ListByUserID(t *testing.T) {
	db, mock, cleanup := testutil.SetupMockDB(t)
	defer cleanup()
	repo := NewFederatedIdentityRepository(db)

	rows := sqlmock.NewRows([]string{"id", "user_id", "idp_issuer", "idp_sub", "created_at"}).
		AddRow("fi-1", "user-1", "https://idp-a.example.com", "sub-a", time.Now().UTC()).
		AddRow("fi-2", "user-1", "https://idp-b.example.com", "sub-b", time.Now().UTC())
	mock.ExpectQuery(`SELECT id, user_id, idp_issuer, idp_sub, created_at FROM federated_identities WHERE user_id=\$1 ORDER BY created_at`).
		WithArgs("user-1").
		WillReturnRows(rows)

	list, err := repo.ListByUserID(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestUserRepository_GetUserByEmailInsensitive(t *testing.T) {
	db, mock, cleanup := testutil.SetupMockDB(t)
	defer cleanup()
	repo := NewUserRepository(db)

	t.Run("matches regardless of stored casing", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "email", "name", "type", "language", "created_at", "updated_at"}).
			AddRow("u-1", "Jane@Corp.com", "Jane", domain.UserTypeUser, "en", time.Now().UTC(), time.Now().UTC())
		mock.ExpectQuery(`SELECT id, email, name, type, language, created_at, updated_at FROM users WHERE lower\(email\)=lower\(\$1\)`).
			WithArgs("jane@corp.com").
			WillReturnRows(rows)

		u, err := repo.GetUserByEmailInsensitive(context.Background(), "jane@corp.com")
		require.NoError(t, err)
		assert.Equal(t, "Jane@Corp.com", u.Email)
	})

	t.Run("no row maps to ErrUserNotFound", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id, email, name, type, language, created_at, updated_at FROM users WHERE lower\(email\)=lower\(\$1\)`).
			WithArgs("nobody@corp.com").
			WillReturnError(sql.ErrNoRows)

		_, err := repo.GetUserByEmailInsensitive(context.Background(), "nobody@corp.com")
		var notFound *domain.ErrUserNotFound
		assert.True(t, errors.As(err, &notFound), "expected *ErrUserNotFound, got %v", err)
	})
}
