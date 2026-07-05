import React, { useRef, useState } from 'react'
import { useLingui } from '@lingui/react/macro'
import { useQueryClient } from '@tanstack/react-query'
import { Button, Modal, App, Tooltip } from 'antd'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faFileExport, faFileImport, faTriangleExclamation } from '@fortawesome/free-solid-svg-icons'
import {
  transactionalNotificationsApi,
  TransactionalNotification
} from '../../services/api/transactional_notifications'
import { templatesApi, Template } from '../../services/api/template'
import { ApiError } from '../../services/api/client'

// Bundle format written to / read from the exported JSON file.
const BUNDLE_TYPE = 'transactional-notification'
const BUNDLE_VERSION = '1.0'

interface TransactionalBundle {
  type: typeof BUNDLE_TYPE
  version: string
  exportedAt: string
  notification: TransactionalNotification
  template: Template | null
}

// Sanitize a name for use as a download filename.
const sanitizeFilename = (name: string): string => {
  const cleaned = name
    .replace(/[/\\?%*:|"<>]/g, '-')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase()
  return cleaned || 'transactional-notification'
}

// Trigger a browser download for the given text content.
const downloadFile = (content: string, filename: string, contentType: string) => {
  const blob = new Blob([content], { type: contentType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

// Returns the existing resource if found, or null on a 404. Other errors propagate.
const getOrNull = async <T,>(promise: Promise<T>): Promise<T | null> => {
  try {
    return await promise
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null
    }
    throw error
  }
}

// === EXPORT ===

interface ExportNotificationButtonProps {
  workspaceId: string
  notification: TransactionalNotification
}

export const ExportNotificationButton: React.FC<ExportNotificationButtonProps> = ({
  workspaceId,
  notification
}) => {
  const { t } = useLingui()
  const { message } = App.useApp()
  const [loading, setLoading] = useState(false)

  const handleExport = async () => {
    setLoading(true)
    try {
      // Fetch the freshest notification config.
      const notificationResponse = await transactionalNotificationsApi.get({
        workspace_id: workspaceId,
        id: notification.id
      })

      // Bundle the email channel's template alongside the notification (managed
      // separately in the UI, but exported together so an import recreates both).
      let template: Template | null = null
      const templateId = notificationResponse.notification.channels?.email?.template_id
      if (templateId) {
        const templateResponse = await templatesApi.get({
          workspace_id: workspaceId,
          id: templateId
        })
        template = templateResponse.template
      }

      const bundle: TransactionalBundle = {
        type: BUNDLE_TYPE,
        version: BUNDLE_VERSION,
        exportedAt: new Date().toISOString(),
        notification: notificationResponse.notification,
        template
      }

      downloadFile(
        JSON.stringify(bundle, null, 2),
        `${sanitizeFilename(notification.name)}.json`,
        'application/json'
      )
      message.success(t`Notification exported successfully`)
    } catch (error) {
      console.error('Transactional export failed:', error)
      message.error(t`Failed to export notification`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Tooltip title={t`Export`}>
      <Button type="text" size="small" loading={loading} onClick={handleExport}>
        <FontAwesomeIcon icon={faFileExport} style={{ opacity: 0.7 }} />
      </Button>
    </Tooltip>
  )
}

// === IMPORT ===

interface ImportNotificationButtonProps {
  workspaceId: string
  disabled?: boolean
}

// Validate the parsed file is a transactional notification bundle.
const validateBundle = (parsed: unknown): { bundle?: TransactionalBundle; error?: string } => {
  if (!parsed || typeof parsed !== 'object') {
    return { error: 'Invalid file: not a JSON object' }
  }
  const obj = parsed as Record<string, unknown>
  if (obj.type !== BUNDLE_TYPE) {
    return { error: 'Invalid file: not a transactional notification export' }
  }
  const notification = obj.notification as TransactionalNotification | undefined
  if (!notification || typeof notification.id !== 'string' || typeof notification.name !== 'string') {
    return { error: 'Invalid file: missing notification data' }
  }
  return { bundle: obj as unknown as TransactionalBundle }
}

export const ImportNotificationButton: React.FC<ImportNotificationButtonProps> = ({
  workspaceId,
  disabled
}) => {
  const { t } = useLingui()
  const { message, modal } = App.useApp()
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [loading, setLoading] = useState(false)

  const triggerFilePicker = () => fileInputRef.current?.click()

  // Upsert the template (if bundled) then the notification. Template first so the
  // notification's channel reference points at an existing template.
  const performImport = async (bundle: TransactionalBundle) => {
    setLoading(true)
    try {
      if (bundle.template) {
        const tpl = bundle.template
        const existing = await getOrNull(
          templatesApi.get({ workspace_id: workspaceId, id: tpl.id })
        )
        const templatePayload = {
          workspace_id: workspaceId,
          id: tpl.id,
          name: tpl.name,
          channel: tpl.channel,
          email: tpl.email,
          web: tpl.web,
          category: tpl.category,
          template_macro_id: tpl.template_macro_id,
          test_data: tpl.test_data,
          settings: tpl.settings,
          translations: tpl.translations
        }
        if (existing) {
          await templatesApi.update(templatePayload)
        } else {
          await templatesApi.create(templatePayload)
        }
      }

      const n = bundle.notification
      const existingNotification = await getOrNull(
        transactionalNotificationsApi.get({ workspace_id: workspaceId, id: n.id })
      )
      if (existingNotification) {
        await transactionalNotificationsApi.update({
          workspace_id: workspaceId,
          id: n.id,
          updates: {
            name: n.name,
            description: n.description,
            channels: n.channels,
            tracking_settings: n.tracking_settings,
            metadata: n.metadata
          }
        })
      } else {
        await transactionalNotificationsApi.create({
          workspace_id: workspaceId,
          notification: {
            id: n.id,
            name: n.name,
            description: n.description,
            // Integration-managed notifications import as plain notifications;
            // integration_id is intentionally dropped (cannot be reattached here).
            channels: n.channels,
            tracking_settings: n.tracking_settings,
            metadata: n.metadata
          }
        })
      }

      queryClient.invalidateQueries({ queryKey: ['transactional-notifications', workspaceId] })
      message.success(t`Notification imported successfully`)
    } catch (error) {
      console.error('Transactional import failed:', error)
      message.error(t`Failed to import notification`)
    } finally {
      setLoading(false)
    }
  }

  // Check for existing notification / template by ID and confirm before overwriting.
  const confirmAndImport = async (bundle: TransactionalBundle) => {
    setLoading(true)
    let existingNotification: TransactionalNotification | null = null
    let existingTemplate: Template | null = null
    try {
      existingNotification = (
        await getOrNull(
          transactionalNotificationsApi.get({ workspace_id: workspaceId, id: bundle.notification.id })
        )
      )?.notification ?? null

      if (bundle.template) {
        existingTemplate = (
          await getOrNull(
            templatesApi.get({ workspace_id: workspaceId, id: bundle.template.id })
          )
        )?.template ?? null
      }
    } catch (error) {
      console.error('Transactional import conflict check failed:', error)
      message.error(t`Failed to read existing data`)
      setLoading(false)
      return
    }
    setLoading(false)

    const conflicts: string[] = []
    if (existingNotification) {
      conflicts.push(t`Notification "${existingNotification.name}" (${bundle.notification.id})`)
    }
    if (existingTemplate) {
      conflicts.push(t`Template "${existingTemplate.name}" (${bundle.template!.id})`)
    }

    if (conflicts.length === 0) {
      await performImport(bundle)
      return
    }

    modal.confirm({
      title: t`Overwrite existing data?`,
      icon: <FontAwesomeIcon icon={faTriangleExclamation} className="text-orange-500 mr-2" />,
      content: (
        <div>
          <p>{t`The following already exist and will be updated:`}</p>
          <ul className="mt-2 ml-4 list-disc">
            {conflicts.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      ),
      okText: t`Yes, Update`,
      cancelText: t`Cancel`,
      onOk: () => performImport(bundle)
    })
  }

  const handleFileInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = '' // allow re-selecting the same file
    if (!file) return

    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(e.target?.result as string)
        const { bundle, error } = validateBundle(parsed)
        if (error || !bundle) {
          Modal.error({
            title: t`Import Failed`,
            content: error || t`Invalid file format`
          })
          return
        }
        confirmAndImport(bundle)
      } catch (err) {
        console.error('Failed to parse import file:', err)
        Modal.error({
          title: t`Import Failed`,
          content: t`Could not parse the file. Please select a valid JSON export.`
        })
      }
    }
    reader.onerror = () => message.error(t`Failed to read the file`)
    reader.readAsText(file)
  }

  return (
    <>
      <Button loading={loading} disabled={disabled} onClick={triggerFilePicker}>
        <FontAwesomeIcon icon={faFileImport} className="mr-2" />
        {t`Import`}
      </Button>
      <input
        ref={fileInputRef}
        type="file"
        accept=".json,application/json"
        style={{ display: 'none' }}
        onChange={handleFileInputChange}
      />
    </>
  )
}
