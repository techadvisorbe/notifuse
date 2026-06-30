package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/Notifuse/notifuse/internal/domain"
	"github.com/Notifuse/notifuse/pkg/logger"
)

// WebhookRegistrationService implements the domain.WebhookRegistrationService interface
type WebhookRegistrationService struct {
	workspaceRepo    domain.WorkspaceRepository
	authService      domain.AuthService
	logger           logger.Logger
	apiEndpoint      string
	webhookProviders map[domain.EmailProviderKind]domain.WebhookProvider
}

// NewWebhookRegistrationService creates a new webhook registration service
func NewWebhookRegistrationService(
	workspaceRepo domain.WorkspaceRepository,
	authService domain.AuthService,
	postmarkService domain.PostmarkServiceInterface,
	mailgunService domain.MailgunServiceInterface,
	mailjetService domain.MailjetServiceInterface,
	sparkPostService domain.SparkPostServiceInterface,
	sesService domain.SESServiceInterface,
	sendGridService domain.SendGridServiceInterface,
	logger logger.Logger,
	apiEndpoint string,
) *WebhookRegistrationService {
	// Create the service
	svc := &WebhookRegistrationService{
		workspaceRepo:    workspaceRepo,
		authService:      authService,
		logger:           logger,
		apiEndpoint:      apiEndpoint,
		webhookProviders: make(map[domain.EmailProviderKind]domain.WebhookProvider),
	}

	// Register services that implement the WebhookProvider interface
	if provider, ok := sparkPostService.(domain.WebhookProvider); ok {
		svc.webhookProviders[domain.EmailProviderKindSparkPost] = provider
	}

	if provider, ok := postmarkService.(domain.WebhookProvider); ok {
		svc.webhookProviders[domain.EmailProviderKindPostmark] = provider
	}

	if provider, ok := mailgunService.(domain.WebhookProvider); ok {
		svc.webhookProviders[domain.EmailProviderKindMailgun] = provider
	}

	if provider, ok := mailjetService.(domain.WebhookProvider); ok {
		svc.webhookProviders[domain.EmailProviderKindMailjet] = provider
	}

	if provider, ok := sesService.(domain.WebhookProvider); ok {
		svc.webhookProviders[domain.EmailProviderKindSES] = provider
	}

	if provider, ok := sendGridService.(domain.WebhookProvider); ok {
		svc.webhookProviders[domain.EmailProviderKindSendGrid] = provider
	}

	return svc
}

// RegisterWebhooks registers webhook URLs with the email provider
func (s *WebhookRegistrationService) RegisterWebhooks(
	ctx context.Context,
	workspaceID string,
	config *domain.WebhookRegistrationConfig,
) (*domain.WebhookRegistrationStatus, error) {
	// Authenticate the user for this workspace
	ctx, _, _, err := s.authService.AuthenticateUserForWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate user: %w", err)
	}

	// Get email provider configuration from workspace settings
	emailProvider, err := s.getEmailProviderConfig(ctx, workspaceID, config.IntegrationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get email provider configuration: %w", err)
	}

	// Convert webhook base URL if needed (remove trailing slash)
	baseURL := strings.TrimSuffix(s.apiEndpoint, "/")

	// Get provider implementation
	provider, ok := s.webhookProviders[emailProvider.Kind]
	if !ok {
		return nil, fmt.Errorf("webhook registration not implemented for provider: %s", emailProvider.Kind)
	}

	// Delegate to provider implementation with the provider configuration
	status, err := provider.RegisterWebhooks(ctx, workspaceID, config.IntegrationID, baseURL, config.EventTypes, emailProvider)
	if err != nil {
		return nil, err
	}

	// For providers whose inbound (reply) mail arrives via a provider-side route rather
	// than an event webhook (e.g. Mailgun Routes), also register that route so
	// stop-on-reply works without manual ESP setup. Providers that don't support this
	// simply don't implement the interface, so this step is skipped for them.
	//
	// Inbound provisioning is BEST-EFFORT relative to the primary registration: it uses a
	// different (often broader) permission surface, so on failure we log and still return the
	// already-succeeded delivery/bounce/complaint status rather than reporting the whole
	// "Register Webhooks" action as failed. GetWebhookStatus surfaces inbound_registered=false.
	if registrar, ok := provider.(domain.InboundRouteRegistrar); ok {
		inboundURL := domain.GenerateInboundWebhookURL(baseURL, workspaceID, config.IntegrationID)
		if err := registrar.EnsureInboundRoute(ctx, emailProvider, inboundURL); err != nil {
			s.logger.WithField("workspace_id", workspaceID).
				WithField("integration_id", config.IntegrationID).
				WithField("provider", string(emailProvider.Kind)).
				Warn("Inbound reply route registration failed; stop-on-reply unavailable until resolved: " + err.Error())
		} else if emailProvider.Kind == domain.EmailProviderKindSES &&
			emailProvider.SES != nil && emailProvider.SES.InboundTopicARN != "" {
			// Persist the provisioned SNS topic ARN so the inbound parser can bind to it
			// (the authentication check that a message came from OUR topic). Best-effort:
			// a persistence failure leaves inbound unauthenticated-and-rejected, not open.
			if err := s.persistSESInboundTopicARN(ctx, workspaceID, config.IntegrationID, emailProvider.SES.InboundTopicARN); err != nil {
				s.logger.WithField("workspace_id", workspaceID).
					WithField("integration_id", config.IntegrationID).
					Warn("Failed to persist SES inbound topic ARN; inbound replies will be rejected until re-registered: " + err.Error())
			}
		}
	}

	return status, nil
}

// persistSESInboundTopicARN saves the provisioned inbound SNS topic ARN onto the integration's
// SES settings so the inbound parser can bind to it. Re-saving the workspace round-trips the
// integration secrets through BeforeSave/AfterLoad encryption (same pattern as UpdateIntegration).
func (s *WebhookRegistrationService) persistSESInboundTopicARN(ctx context.Context, workspaceID, integrationID, arn string) error {
	if arn == "" {
		return nil
	}
	workspace, err := s.workspaceRepo.GetByID(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to load workspace: %w", err)
	}
	integration := workspace.GetIntegrationByID(integrationID)
	if integration == nil || integration.EmailProvider.SES == nil {
		return fmt.Errorf("SES integration %s not found", integrationID)
	}
	if integration.EmailProvider.SES.InboundTopicARN == arn {
		return nil // already persisted
	}
	integration.EmailProvider.SES.InboundTopicARN = arn // GetIntegrationByID returns a slice pointer
	return s.workspaceRepo.Update(ctx, workspace)
}

// GetWebhookStatus gets the status of webhooks for an email provider
func (s *WebhookRegistrationService) GetWebhookStatus(
	ctx context.Context,
	workspaceID string,
	integrationID string,
) (*domain.WebhookRegistrationStatus, error) {
	// Authenticate the user for this workspace
	ctx, _, _, err := s.authService.AuthenticateUserForWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate user: %w", err)
	}

	// Get email provider configuration from workspace settings
	emailProvider, err := s.getEmailProviderConfig(ctx, workspaceID, integrationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get email provider configuration: %w", err)
	}

	// Get provider implementation
	provider, ok := s.webhookProviders[emailProvider.Kind]
	if !ok {
		return nil, fmt.Errorf("webhook status check not implemented for provider: %s", emailProvider.Kind)
	}

	// Delegate to provider implementation with the provider configuration
	return provider.GetWebhookStatus(ctx, workspaceID, integrationID, emailProvider)
}

// UnregisterWebhooks removes all webhook URLs associated with the integration
func (s *WebhookRegistrationService) UnregisterWebhooks(
	ctx context.Context,
	workspaceID string,
	integrationID string,
) error {
	// Authenticate the user for this workspace
	ctx, _, _, err := s.authService.AuthenticateUserForWorkspace(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to authenticate user: %w", err)
	}

	// Get email provider configuration from workspace settings
	emailProvider, err := s.getEmailProviderConfig(ctx, workspaceID, integrationID)
	if err != nil {
		return fmt.Errorf("failed to get email provider configuration: %w", err)
	}

	// Get provider implementation
	provider, ok := s.webhookProviders[emailProvider.Kind]
	if !ok {
		return fmt.Errorf("webhook unregistration not implemented for provider: %s", emailProvider.Kind)
	}

	// Delegate to provider implementation with the provider configuration
	return provider.UnregisterWebhooks(ctx, workspaceID, integrationID, emailProvider)
}

// getEmailProviderConfig gets the email provider configuration from workspace settings
func (s *WebhookRegistrationService) getEmailProviderConfig(ctx context.Context, workspaceID string, integrationID string) (*domain.EmailProvider, error) {
	// Get workspace settings from the database
	workspace, err := s.workspaceRepo.GetByID(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workspace: %w", err)
	}

	// Find the integration by ID
	integration := workspace.GetIntegrationByID(integrationID)
	if integration == nil {
		return nil, fmt.Errorf("integration with ID %s not found", integrationID)
	}

	return &integration.EmailProvider, nil
}
