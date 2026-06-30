import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { App, ConfigProvider } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { i18n } from '@lingui/core'
import { I18nProvider } from '@lingui/react'
import { BlogSettings } from './BlogSettings'
import type { Workspace } from '../../services/api/types'
import { workspaceService } from '../../services/api/workspace'

// Blog settings must be saved via the dedicated, blog:write-gated endpoint
// (setBlogSettings) and NOT via the owner-only workspaces.update.
vi.mock('../../services/api/workspace', () => ({
  workspaceService: {
    setBlogSettings: vi.fn().mockResolvedValue({ status: 'success' }),
    update: vi.fn(),
    get: vi.fn().mockResolvedValue({
      workspace: { id: 'ws1', settings: { blog_enabled: true } }
    })
  }
}))

vi.mock('../../services/api/blog', () => ({
  blogThemesApi: {
    list: vi.fn().mockResolvedValue({ themes: [{ version: 1 }] }),
    create: vi.fn(),
    publish: vi.fn()
  }
}))

// Stub heavy child components that pull in their own data/context dependencies
// (file-manager context, react-query, drawers); they are out of scope here.
vi.mock('../blog/RecentThemesTable', () => ({
  RecentThemesTable: () => <div data-testid="recent-themes" />
}))
vi.mock('../common/ImageURLInput', () => ({
  ImageURLInput: () => <input data-testid="image-url-input" />
}))
vi.mock('../seo/SEOSettingsForm', () => ({
  SEOSettingsForm: () => <div data-testid="seo-form" />
}))

// Empty messages: the Lingui macro falls back to the source text as the message.
i18n.loadAndActivate({ locale: 'en', messages: {} })

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })

const makeWorkspace = (settingsOverrides: Record<string, unknown> = {}): Workspace =>
  ({
    id: 'ws1',
    name: 'My Blog WS',
    settings: {
      timezone: 'UTC',
      custom_endpoint_url: 'https://blog.example.com',
      blog_enabled: true,
      blog_settings: { title: 'Existing Title' },
      ...settingsOverrides
    }
  }) as unknown as Workspace

const renderComponent = (canManage: boolean, workspace: Workspace | null = makeWorkspace()) =>
  render(
    <QueryClientProvider client={queryClient}>
      <I18nProvider i18n={i18n}>
        <ConfigProvider>
          <App>
            <BlogSettings workspace={workspace} onWorkspaceUpdate={vi.fn()} canManage={canManage} />
          </App>
        </ConfigProvider>
      </I18nProvider>
    </QueryClientProvider>
  )

describe('BlogSettings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders a read-only view (no editor) when the user cannot manage', () => {
    renderComponent(false, makeWorkspace({ blog_enabled: false }))
    // No editor controls are rendered for non-managers.
    expect(screen.queryByRole('button', { name: /Save Changes/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /Enable Blog/i })).toBeNull()
    // The read-only status is shown instead.
    expect(screen.getByText(/Disabled/)).toBeInTheDocument()
  })

  it('renders the editable form when the user can manage and the blog is enabled', () => {
    renderComponent(true)
    expect(screen.getByRole('button', { name: /Save Changes/i })).toBeInTheDocument()
  })

  it('saves via setBlogSettings (not workspace.update)', async () => {
    renderComponent(true)

    // Change the blog title to mark the form as touched (enables the Save button).
    const titleInput = screen.getByPlaceholderText('My Blog WS')
    fireEvent.change(titleInput, { target: { value: 'New Blog Title' } })

    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))

    await waitFor(() => {
      expect(workspaceService.setBlogSettings).toHaveBeenCalledWith(
        expect.objectContaining({
          workspace_id: 'ws1',
          blog_enabled: true
        })
      )
    })
    expect(workspaceService.update).not.toHaveBeenCalled()
  })
})
