package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsDevelopment(t *testing.T) {
	// Test development environment
	cfg := &Config{
		Environment: "development",
	}
	assert.True(t, cfg.IsDevelopment())

	// Test production environment
	cfg = &Config{
		Environment: "production",
	}
	assert.False(t, cfg.IsDevelopment())

	// Test staging environment
	cfg = &Config{
		Environment: "staging",
	}
	assert.False(t, cfg.IsDevelopment())
}

func TestLoadWithOptions(t *testing.T) {
	// Set environment variables for the test
	_ = os.Setenv("SECRET_KEY", "test-secret-key-1234567890123456") // 32 bytes
	_ = os.Setenv("ROOT_EMAIL", "test@example.com")
	_ = os.Setenv("SERVER_PORT", "9000")
	_ = os.Setenv("SERVER_HOST", "127.0.0.1")
	_ = os.Setenv("DB_HOST", "testhost")
	_ = os.Setenv("DB_PORT", "5432")
	_ = os.Setenv("DB_USER", "testuser")
	_ = os.Setenv("DB_PASSWORD", "testpass")
	_ = os.Setenv("DB_PREFIX", "test")
	_ = os.Setenv("DB_NAME", "test_system")
	_ = os.Setenv("ENVIRONMENT", "development")

	// Clean up after the test
	defer func() {
		_ = os.Unsetenv("SECRET_KEY")
		_ = os.Unsetenv("ROOT_EMAIL")
		_ = os.Unsetenv("SERVER_PORT")
		_ = os.Unsetenv("SERVER_HOST")
		_ = os.Unsetenv("DB_HOST")
		_ = os.Unsetenv("DB_PORT")
		_ = os.Unsetenv("DB_USER")
		_ = os.Unsetenv("DB_PASSWORD")
		_ = os.Unsetenv("DB_PREFIX")
		_ = os.Unsetenv("DB_NAME")
		_ = os.Unsetenv("ENVIRONMENT")
	}()

	// Load config with env vars
	cfg, err := LoadWithOptions(LoadOptions{
		// Don't specify EnvFile to force it to use environment variables
	})
	require.NoError(t, err)

	// Verify loaded config values
	assert.Equal(t, 9000, cfg.Server.Port)
	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, "testhost", cfg.Database.Host)
	assert.Equal(t, 5432, cfg.Database.Port)
	assert.Equal(t, "testuser", cfg.Database.User)
	assert.Equal(t, "testpass", cfg.Database.Password)
	assert.Equal(t, "test", cfg.Database.Prefix)
	assert.Equal(t, "test_system", cfg.Database.DBName)
	assert.Equal(t, "test@example.com", cfg.RootEmail)
	assert.Equal(t, "development", cfg.Environment)

	// Verify JWT secret and SecretKey
	assert.Equal(t, "test-secret-key-1234567890123456", cfg.Security.SecretKey)
	assert.NotNil(t, cfg.Security.JWTSecret)
	assert.GreaterOrEqual(t, len(cfg.Security.JWTSecret), 32)

	// Test development environment flag
	assert.True(t, cfg.IsDevelopment())
}

func TestLoad_DataFeedSSRFProtectionDefault(t *testing.T) {
	// SECRET_KEY is required for the config to load successfully.
	_ = os.Setenv("SECRET_KEY", "test-secret-key-1234567890123456")
	defer func() { _ = os.Unsetenv("SECRET_KEY") }()

	t.Run("defaults to off (SSRF protection enabled)", func(t *testing.T) {
		_ = os.Unsetenv("BROADCAST_DATA_FEED_ALLOW_PRIVATE_HOSTS")

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		// Secure by default: a missing/typo'd env key must NOT disable protection.
		assert.False(t, cfg.Broadcast.AllowPrivateDataFeedHosts,
			"broadcast data-feed SSRF protection must be ON by default")
	})

	t.Run("opt-in via env var", func(t *testing.T) {
		_ = os.Setenv("BROADCAST_DATA_FEED_ALLOW_PRIVATE_HOSTS", "true")
		defer func() { _ = os.Unsetenv("BROADCAST_DATA_FEED_ALLOW_PRIVATE_HOSTS") }()

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.True(t, cfg.Broadcast.AllowPrivateDataFeedHosts)
	})
}

func TestLoad_ServerMode(t *testing.T) {
	// SECRET_KEY is required for the config to load successfully.
	_ = os.Setenv("SECRET_KEY", "test-secret-key-1234567890123456")
	defer func() { _ = os.Unsetenv("SECRET_KEY") }()

	t.Run("defaults to all", func(t *testing.T) {
		_ = os.Unsetenv("SERVER_MODE")

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.Equal(t, ServerModeAll, cfg.Server.Mode)
		assert.False(t, cfg.IsPublicMode())
	})

	t.Run("public mode", func(t *testing.T) {
		_ = os.Setenv("SERVER_MODE", "public")
		defer func() { _ = os.Unsetenv("SERVER_MODE") }()

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.Equal(t, ServerModePublic, cfg.Server.Mode)
		assert.True(t, cfg.IsPublicMode())
	})

	t.Run("mode is case-insensitive and trimmed", func(t *testing.T) {
		_ = os.Setenv("SERVER_MODE", " Public ")
		defer func() { _ = os.Unsetenv("SERVER_MODE") }()

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.True(t, cfg.IsPublicMode())
	})

	t.Run("invalid mode fails boot", func(t *testing.T) {
		_ = os.Setenv("SERVER_MODE", "console")
		defer func() { _ = os.Unsetenv("SERVER_MODE") }()

		_, err := LoadWithOptions(LoadOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SERVER_MODE")
	})

	t.Run("extra public paths are parsed and normalized", func(t *testing.T) {
		_ = os.Setenv("SERVER_MODE", "public")
		_ = os.Setenv("SERVER_PUBLIC_EXTRA_PATHS", "/api/cron, api/transactional.send ,, /custom/")
		defer func() {
			_ = os.Unsetenv("SERVER_MODE")
			_ = os.Unsetenv("SERVER_PUBLIC_EXTRA_PATHS")
		}()

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.Equal(t, []string{"/api/cron", "/api/transactional.send", "/custom/"}, cfg.Server.PublicExtraPaths)
	})
}

func TestLoad_ConsoleEndpoint(t *testing.T) {
	// SECRET_KEY is required for the config to load successfully.
	_ = os.Setenv("SECRET_KEY", "test-secret-key-1234567890123456")
	_ = os.Setenv("API_ENDPOINT", "https://public.example.com")
	defer func() {
		_ = os.Unsetenv("SECRET_KEY")
		_ = os.Unsetenv("API_ENDPOINT")
	}()

	t.Run("defaults to the API endpoint", func(t *testing.T) {
		_ = os.Unsetenv("CONSOLE_ENDPOINT")

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.Equal(t, "https://public.example.com", cfg.ConsoleEndpoint)
	})

	t.Run("env override with trailing slash trimmed", func(t *testing.T) {
		_ = os.Setenv("CONSOLE_ENDPOINT", "https://intranet.example.com/")
		defer func() { _ = os.Unsetenv("CONSOLE_ENDPOINT") }()

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.Equal(t, "https://intranet.example.com", cfg.ConsoleEndpoint)
		// API endpoint is untouched (still used for public-facing URLs)
		assert.Equal(t, "https://public.example.com", cfg.APIEndpoint)
	})

	t.Run("OIDC redirect URI derives from the console endpoint", func(t *testing.T) {
		// The OIDC callback is a management route served by the instance the
		// console user's browser talks to, so the derived redirect URI must use
		// the console endpoint in a split deployment.
		_ = os.Setenv("CONSOLE_ENDPOINT", "https://intranet.example.com")
		_ = os.Setenv("OIDC_ENABLED", "true")
		_ = os.Setenv("OIDC_ISSUER_URL", "https://idp.example.com")
		_ = os.Setenv("OIDC_CLIENT_ID", "client-id")
		_ = os.Setenv("OIDC_CLIENT_SECRET", "client-secret")
		defer func() {
			_ = os.Unsetenv("CONSOLE_ENDPOINT")
			_ = os.Unsetenv("OIDC_ENABLED")
			_ = os.Unsetenv("OIDC_ISSUER_URL")
			_ = os.Unsetenv("OIDC_CLIENT_ID")
			_ = os.Unsetenv("OIDC_CLIENT_SECRET")
		}()

		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.Equal(t, "https://intranet.example.com/api/user.oidc.callback", cfg.OIDC.RedirectURI)
	})
}

func TestInvalidKeysHandling(t *testing.T) {
	t.Run("missing_secret_key", func(t *testing.T) {
		// Clear any existing environment variables
		_ = os.Unsetenv("SECRET_KEY")
		_ = os.Unsetenv("PASETO_PRIVATE_KEY")

		// Test missing SECRET_KEY
		_, err := LoadWithOptions(LoadOptions{})
		require.Error(t, err)
		assert.Equal(t, "SECRET_KEY (or PASETO_PRIVATE_KEY for backward compatibility) must be set", err.Error())
	})

	t.Run("valid_secret_key", func(t *testing.T) {
		// Clear any existing environment variables first
		_ = os.Unsetenv("SECRET_KEY")
		_ = os.Unsetenv("PASETO_PRIVATE_KEY")

		// Set SECRET_KEY with valid length
		_ = os.Setenv("SECRET_KEY", "test-secret-key-1234567890123456")
		defer func() { _ = os.Unsetenv("SECRET_KEY") }()

		// Should succeed
		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.NotNil(t, cfg.Security.JWTSecret)
		assert.Equal(t, "test-secret-key-1234567890123456", cfg.Security.SecretKey)
	})

	t.Run("backward_compatibility_paseto_private_key", func(t *testing.T) {
		// Clear any existing environment variables first
		_ = os.Unsetenv("SECRET_KEY")
		_ = os.Unsetenv("PASETO_PRIVATE_KEY")

		// Set only PASETO_PRIVATE_KEY (backward compatibility)
		_ = os.Setenv("PASETO_PRIVATE_KEY", "8OSonZEkrCTlDd612EBoORCKVMZ4OjbWlrq03n0FIEgEJK+qb95F4pwewi+Dd++qOjQ9zkviUjFdIaBUz3nzgA==")
		defer func() { _ = os.Unsetenv("PASETO_PRIVATE_KEY") }()

		// Should succeed with base64-decoded secret
		cfg, err := LoadWithOptions(LoadOptions{})
		require.NoError(t, err)
		assert.NotNil(t, cfg.Security.JWTSecret)
		assert.GreaterOrEqual(t, len(cfg.Security.JWTSecret), 32)
	})
}

func TestLoad(t *testing.T) {
	// Test the Load function by temporarily setting the required environment variables
	// Set environment variables for the test
	_ = os.Setenv("SECRET_KEY", "test-secret-key-1234567890123456")
	_ = os.Setenv("ROOT_EMAIL", "test@example.com")

	// Clean up after the test
	defer func() {
		_ = os.Unsetenv("SECRET_KEY")
		_ = os.Unsetenv("ROOT_EMAIL")
	}()

	// Call Load() directly
	cfg, err := Load()

	// We may get an error if the .env file doesn't exist, but the environment variables
	// should still be processed
	if err != nil {
		// This is an acceptable error if it relates to file loading
		if err.Error() == "SECRET_KEY (or PASETO_PRIVATE_KEY for backward compatibility) must be set" {
			t.Fatal("Environment variables not properly loaded")
		}
	} else {
		assert.NotNil(t, cfg)
		assert.Equal(t, "test@example.com", cfg.RootEmail)
		assert.NotNil(t, cfg.Security.JWTSecret)
	}
}

func TestDatabaseConnectionConfig_Defaults(t *testing.T) {
	// Set minimal required env vars
	_ = os.Setenv("SECRET_KEY", "test-secret-key-for-testing")
	_ = os.Setenv("DB_PASSWORD", "testpass")
	defer func() { _ = os.Unsetenv("SECRET_KEY") }()
	defer func() { _ = os.Unsetenv("DB_PASSWORD") }()

	cfg, err := LoadWithOptions(LoadOptions{})
	require.NoError(t, err)

	// Test default values
	assert.Equal(t, 100, cfg.Database.MaxConnections)
	assert.Equal(t, 3, cfg.Database.MaxConnectionsPerDB)
	assert.Equal(t, 10*time.Minute, cfg.Database.ConnectionMaxLifetime)
	assert.Equal(t, 5*time.Minute, cfg.Database.ConnectionMaxIdleTime)
}

func TestDatabaseConnectionConfig_CustomValues(t *testing.T) {
	// Set custom connection configuration
	_ = os.Setenv("SECRET_KEY", "test-secret-key-for-testing")
	_ = os.Setenv("DB_PASSWORD", "testpass")
	_ = os.Setenv("DB_MAX_CONNECTIONS", "200")
	_ = os.Setenv("DB_MAX_CONNECTIONS_PER_DB", "5")
	_ = os.Setenv("DB_CONNECTION_MAX_LIFETIME", "20m")
	_ = os.Setenv("DB_CONNECTION_MAX_IDLE_TIME", "10m")

	defer func() { _ = os.Unsetenv("SECRET_KEY") }()
	defer func() { _ = os.Unsetenv("DB_PASSWORD") }()
	defer func() { _ = os.Unsetenv("DB_MAX_CONNECTIONS") }()
	defer func() { _ = os.Unsetenv("DB_MAX_CONNECTIONS_PER_DB") }()
	defer func() { _ = os.Unsetenv("DB_CONNECTION_MAX_LIFETIME") }()
	defer func() { _ = os.Unsetenv("DB_CONNECTION_MAX_IDLE_TIME") }()

	cfg, err := LoadWithOptions(LoadOptions{})
	require.NoError(t, err)

	// Test custom values
	assert.Equal(t, 200, cfg.Database.MaxConnections)
	assert.Equal(t, 5, cfg.Database.MaxConnectionsPerDB)
	assert.Equal(t, 20*time.Minute, cfg.Database.ConnectionMaxLifetime)
	assert.Equal(t, 10*time.Minute, cfg.Database.ConnectionMaxIdleTime)
}

func TestDatabaseConnectionConfig_ValidationMinimum(t *testing.T) {
	// Test that MaxConnections below minimum fails
	_ = os.Setenv("SECRET_KEY", "test-secret-key-for-testing")
	_ = os.Setenv("DB_PASSWORD", "testpass")
	_ = os.Setenv("DB_MAX_CONNECTIONS", "10") // Below minimum of 20

	defer os.Unsetenv("SECRET_KEY")
	defer os.Unsetenv("DB_PASSWORD")
	defer os.Unsetenv("DB_MAX_CONNECTIONS")

	_, err := LoadWithOptions(LoadOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB_MAX_CONNECTIONS must be at least 20")
}

func TestDatabaseConnectionConfig_ValidationMaximum(t *testing.T) {
	// Test that MaxConnections above maximum fails
	_ = os.Setenv("SECRET_KEY", "test-secret-key-for-testing")
	_ = os.Setenv("DB_PASSWORD", "testpass")
	_ = os.Setenv("DB_MAX_CONNECTIONS", "15000") // Above maximum of 10000

	defer os.Unsetenv("SECRET_KEY")
	defer os.Unsetenv("DB_PASSWORD")
	defer os.Unsetenv("DB_MAX_CONNECTIONS")

	_, err := LoadWithOptions(LoadOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB_MAX_CONNECTIONS cannot exceed 10000")
}

func TestDatabaseConnectionConfig_ValidationPerDBMinimum(t *testing.T) {
	// Test that MaxConnectionsPerDB below minimum fails
	_ = os.Setenv("SECRET_KEY", "test-secret-key-for-testing")
	_ = os.Setenv("DB_PASSWORD", "testpass")
	_ = os.Setenv("DB_MAX_CONNECTIONS_PER_DB", "0") // Below minimum of 1

	defer os.Unsetenv("SECRET_KEY")
	defer os.Unsetenv("DB_PASSWORD")
	defer func() { _ = os.Unsetenv("DB_MAX_CONNECTIONS_PER_DB") }()

	_, err := LoadWithOptions(LoadOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB_MAX_CONNECTIONS_PER_DB must be at least 1")
}

func TestDatabaseConnectionConfig_ValidationPerDBMaximum(t *testing.T) {
	// Test that MaxConnectionsPerDB above maximum fails
	_ = os.Setenv("SECRET_KEY", "test-secret-key-for-testing")
	_ = os.Setenv("DB_PASSWORD", "testpass")
	_ = os.Setenv("DB_MAX_CONNECTIONS_PER_DB", "60") // Above maximum of 50

	defer os.Unsetenv("SECRET_KEY")
	defer os.Unsetenv("DB_PASSWORD")
	defer func() { _ = os.Unsetenv("DB_MAX_CONNECTIONS_PER_DB") }()

	_, err := LoadWithOptions(LoadOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB_MAX_CONNECTIONS_PER_DB cannot exceed 50")
}

func TestAPIEndpointTrailingSlashStripped(t *testing.T) {
	_ = os.Setenv("SECRET_KEY", "test-secret-key-1234567890123456")
	_ = os.Setenv("API_ENDPOINT", "http://localhost:8081/")
	defer func() { _ = os.Unsetenv("SECRET_KEY") }()
	defer func() { _ = os.Unsetenv("API_ENDPOINT") }()

	cfg, err := LoadWithOptions(LoadOptions{})
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8081", cfg.APIEndpoint)
}
