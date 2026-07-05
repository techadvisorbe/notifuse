import React from 'react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { App, ConfigProvider, Modal } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@lingui/react'
import { i18n } from '@lingui/core'
import {
  ExportNotificationButton,
  ImportNotificationButton
} from './ImportExportTransactional'
import { transactionalNotificationsApi } from '../../services/api/transactional_notifications'
import { templatesApi } from '../../services/api/template'
import { ApiError } from '../../services/api/client'

vi.mock('../../services/api/transactional_notifications', () => ({
  transactionalNotificationsApi: {
    get: vi.fn(),
    create: vi.fn(),
    update: vi.fn()
  }
}))

vi.mock('../../services/api/template', () => ({
  templatesApi: {
    get: vi.fn(),
    create: vi.fn(),
    update: vi.fn()
  }
}))

const txApi = transactionalNotificationsApi as unknown as {
  get: ReturnType<typeof vi.fn>
  create: ReturnType<typeof vi.fn>
  update: ReturnType<typeof vi.fn>
}
const tplApi = templatesApi as unknown as {
  get: ReturnType<typeof vi.fn>
  create: ReturnType<typeof vi.fn>
  update: ReturnType<typeof vi.fn>
}

const notFound = () => new ApiError('not found', 404)

const sampleNotification = {
  id: 'welcome',
  name: 'Welcome Email',
  description: 'desc',
  channels: { email: { template_id: 'tpl-welcome' } },
  tracking_settings: { enable_tracking: true },
  created_at: '',
  updated_at: ''
}

const sampleTemplate = {
  id: 'tpl-welcome',
  name: 'Welcome',
  version: 1,
  channel: 'email',
  category: 'transactional',
  email: { subject: 'Hi', compiled_preview: '', visual_editor_tree: { id: 'r', type: 'mjml' } },
  created_at: '',
  updated_at: ''
}

const renderWith = (ui: React.ReactNode) => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <I18nProvider i18n={i18n}>
        <ConfigProvider>
          <App>{ui}</App>
        </ConfigProvider>
      </I18nProvider>
    </QueryClientProvider>
  )
}

// Build a File whose text() resolves to the given content (jsdom FileReader reads it).
const makeFile = (content: string, name = 'export.json') =>
  new File([content], name, { type: 'application/json' })

const bundleJSON = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    type: 'transactional-notification',
    version: '1.0',
    exportedAt: '2026-01-01T00:00:00.000Z',
    notification: sampleNotification,
    template: sampleTemplate,
    ...overrides
  })

// Imperative Ant modals (Modal.error / modal.confirm) render into document.body
// outside React roots, so RTL cleanup does not remove them. Destroy them between tests
// so leaked modals from a prior test don't satisfy queries in the next one.
afterEach(async () => {
  Modal.destroyAll()
  // Let the close animation finish and React flush the unmount.
  await waitFor(() =>
    expect(document.querySelectorAll('.ant-modal-confirm').length).toBe(0)
  )
})

describe('ExportNotificationButton', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('bundles the notification and its template', async () => {
    txApi.get.mockResolvedValue({ notification: sampleNotification })
    tplApi.get.mockResolvedValue({ template: sampleTemplate })

    const createObjectURL = vi.fn(() => 'blob:url')
    const revokeObjectURL = vi.fn()
    Object.assign(URL, { createObjectURL, revokeObjectURL })

    renderWith(
      <ExportNotificationButton workspaceId="ws1" notification={sampleNotification as never} />
    )

    fireEvent.click(screen.getByRole('button'))

    await waitFor(() => expect(createObjectURL).toHaveBeenCalled())
    expect(txApi.get).toHaveBeenCalledWith({ workspace_id: 'ws1', id: 'welcome' })
    expect(tplApi.get).toHaveBeenCalledWith({ workspace_id: 'ws1', id: 'tpl-welcome' })
  })
})

describe('ImportNotificationButton', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  const uploadFile = (container: HTMLElement, content: string) => {
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [makeFile(content)] } })
  }

  it('creates notification and template when neither exists (no confirm prompt)', async () => {
    txApi.get.mockRejectedValue(notFound())
    tplApi.get.mockRejectedValue(notFound())
    txApi.create.mockResolvedValue({ notification: sampleNotification })
    tplApi.create.mockResolvedValue({ template: sampleTemplate })

    const { container } = renderWith(<ImportNotificationButton workspaceId="ws1" />)
    uploadFile(container, bundleJSON())

    await waitFor(() => expect(tplApi.create).toHaveBeenCalled())
    expect(txApi.create).toHaveBeenCalled()
    expect(txApi.update).not.toHaveBeenCalled()
    expect(tplApi.update).not.toHaveBeenCalled()
    // No confirmation dialog when there are no conflicts.
    expect(screen.queryByText('Overwrite existing data?')).not.toBeInTheDocument()
  })

  it('prompts for confirmation and updates when both exist', async () => {
    txApi.get.mockResolvedValue({ notification: sampleNotification })
    tplApi.get.mockResolvedValue({ template: sampleTemplate })
    txApi.update.mockResolvedValue({ notification: sampleNotification })
    tplApi.update.mockResolvedValue({ template: sampleTemplate })

    const { container } = renderWith(<ImportNotificationButton workspaceId="ws1" />)
    uploadFile(container, bundleJSON())

    const confirmButton = await screen.findByText('Yes, Update')
    fireEvent.click(confirmButton)

    await waitFor(() => expect(tplApi.update).toHaveBeenCalled())
    expect(txApi.update).toHaveBeenCalled()
    expect(txApi.create).not.toHaveBeenCalled()
    expect(tplApi.create).not.toHaveBeenCalled()
  })

  it('does nothing when the confirmation is cancelled', async () => {
    txApi.get.mockResolvedValue({ notification: sampleNotification })
    tplApi.get.mockResolvedValue({ template: sampleTemplate })

    const { container } = renderWith(<ImportNotificationButton workspaceId="ws1" />)
    uploadFile(container, bundleJSON())

    const cancelButton = await screen.findByText('Cancel')
    fireEvent.click(cancelButton)

    await waitFor(() => expect(screen.queryByText('Yes, Update')).not.toBeInTheDocument())
    expect(txApi.update).not.toHaveBeenCalled()
    expect(tplApi.update).not.toHaveBeenCalled()
  })

  it('rejects a file that is not a transactional bundle', async () => {
    const { container } = renderWith(<ImportNotificationButton workspaceId="ws1" />)
    uploadFile(container, JSON.stringify({ type: 'something-else' }))

    // Modal.error renders the title in more than one node (heading + a11y mirror),
    // so assert at least one match rather than a unique one.
    const matches = await screen.findAllByText('Import Failed')
    expect(matches.length).toBeGreaterThan(0)
    expect(txApi.get).not.toHaveBeenCalled()
  })
})
