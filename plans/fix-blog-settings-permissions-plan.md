# Move blog settings to a dedicated `blog:write` endpoint

Follow-up to the custom-fields fix (#354 / `fix-custom-fields-permissions-plan.md`). Same pattern, applied to blog settings.

## 1. Problem

`BlogEnabled` + `BlogSettings` (workspace-level blog config) are written only by the owner-only `UpdateWorkspace` (`workspace_service.go:380-381`), and the console `BlogSettings.tsx` gates the whole editor on `isOwner`. Yet the blog feature has a dedicated **`blog:write`** permission that is already enforced on **11 write paths** (posts, themes, categories). So a member granted `blog:write` — a delegated "blog manager" — can write posts and themes but **cannot enable the blog or change its title/SEO/pagination**. Same gap as custom fields, one layer over.

## 2. Decisions

1. **Permission gate: `blog:write`** (`PermissionResourceBlog` + `PermissionTypeWrite`). Owners always pass; blog-managers with `blog:write` pass. (Not `workspace:write`: the permission follows the *feature*, and blog has its own. See discussion in the conversation.)
2. **Dedicated endpoint is sole writer**: `POST /api/workspaces.setBlogSettings`; remove the blog writes from `UpdateWorkspace` so an owner's general-settings save can't clobber blog config set by a blog-manager.
3. **Service home: `WorkspaceService.SetBlogSettings`** (not `BlogService`). Rationale:
   - Mirrors `SetCustomFieldLabels` exactly ("similar to custom labels") — same service, namespace, structure.
   - **Entity ownership**: blog settings are fields of the `WorkspaceSettings` entity; `WorkspaceService` owns workspace mutation via `WorkspaceRepository.Update`. `BlogService`'s `workspaceRepository` is used for read-context, not settings mutation. Hosting it in `BlogService` would split workspace-entity writes across two services.
   - The `blog:write` gate is orthogonal to the service home: `userWorkspace.HasPermission(blog, write)` works anywhere.
   - *Alternative considered*: `BlogService` + `/api/blogSettings.update` (more feature-cohesive, and `BlogService` has the workspace repo). Rejected for the entity-ownership + custom-fields-symmetry reasons above. Cheap to revisit.
4. **UX: keep the existing read-only-vs-editable split**, driven by a new `canManage` prop instead of `isOwner` (BlogSettings.tsx already renders a read-only `Descriptions` view for non-managers — no disable/tooltip needed, so likely **no new i18n strings**).
5. **No version bump** (32.3 not deployed); changelog bullet added to the existing 32.3 section.

## 3. Backend changes

### 3.1 `internal/domain/workspace.go`
- **Add `BlogSettings.Validate()`** (none exists today; getters clamp on read, so this is light hygiene that also guards non-console API callers):
  ```go
  func (bs *BlogSettings) Validate() error {
      if bs == nil { return nil }
      if len(bs.Title) > 255 { return fmt.Errorf("blog title exceeds maximum length of 255 characters") }
      if bs.HomePageSize != 0 && (bs.HomePageSize < 1 || bs.HomePageSize > 100) { return fmt.Errorf("home_page_size must be between 1 and 100") }
      if bs.CategoryPageSize != 0 && (bs.CategoryPageSize < 1 || bs.CategoryPageSize > 100) { return fmt.Errorf("category_page_size must be between 1 and 100") }
      if bs.FeedMaxItems != 0 && (bs.FeedMaxItems < 1 || bs.FeedMaxItems > 20) { return fmt.Errorf("feed_max_items must be between 1 and 20") }
      return nil
  }
  ```
  (Scope: bounded numerics + title. URL/SEO fields left lenient — frontend constrains them and getters clamp sizes. Can extend later.)
- **Add request type** (near `SetCustomFieldLabelsRequest`):
  ```go
  type SetBlogSettingsRequest struct {
      WorkspaceID  string        `json:"workspace_id"`
      BlogEnabled  bool          `json:"blog_enabled"`
      BlogSettings *BlogSettings `json:"blog_settings"`
  }
  func (r *SetBlogSettingsRequest) Validate() (workspaceID string, enabled bool, settings *BlogSettings, err error) {
      // workspace_id: required, alphanumeric, <=32 (same as SetCustomFieldLabelsRequest)
      // if r.BlogSettings != nil { if err := r.BlogSettings.Validate(); err != nil { return ... } }
      return r.WorkspaceID, r.BlogEnabled, r.BlogSettings, nil
  }
  ```
- **Add to `WorkspaceServiceInterface`** (after `SetCustomFieldLabels`):
  ```go
  SetBlogSettings(ctx context.Context, workspaceID string, enabled bool, settings *BlogSettings) error
  ```

### 3.2 `internal/service/workspace_service.go`
- **New method** (mirrors `SetCustomFieldLabels` — auth → `HasPermission(blog, write)` → load → set only blog fields → validate → Update):
  ```go
  func (s *WorkspaceService) SetBlogSettings(ctx context.Context, workspaceID string, enabled bool, settings *domain.BlogSettings) error {
      ctx, _, userWorkspace, err := s.authService.AuthenticateUserForWorkspace(ctx, workspaceID)
      if err != nil { return fmt.Errorf("failed to authenticate user: %w", err) }
      if !userWorkspace.HasPermission(domain.PermissionResourceBlog, domain.PermissionTypeWrite) {
          return domain.NewPermissionError(domain.PermissionResourceBlog, domain.PermissionTypeWrite,
              "Insufficient permissions: write access to blog required")
      }
      existing, err := s.repo.GetByID(ctx, workspaceID)
      if err != nil { return err }
      existing.Settings.BlogEnabled = enabled
      existing.Settings.BlogSettings = settings
      if err := existing.Settings.BlogSettings.Validate(); err != nil { return err } // canonical
      return s.repo.Update(ctx, existing)
  }
  ```
- **Remove blog writes from `UpdateWorkspace`** (`:380-381`): delete `existingWorkspace.Settings.BlogEnabled = settings.BlogEnabled` and `existingWorkspace.Settings.BlogSettings = settings.BlogSettings`; add the same explanatory comment used for custom field labels. Existing blog config on `existingWorkspace` is preserved.

### 3.3 `internal/http/workspace_handler.go`
- Route in `RegisterRoutes` (next to `setCustomFieldLabels`): `mux.Handle("/api/workspaces.setBlogSettings", requireAuth(http.HandlerFunc(h.handleSetBlogSettings)))`. (Plain `requireAuth`, matching the workspaces namespace and preserving today's behavior — blog settings currently flow through `workspaces.update`, which is not `restrictedInDemo`.)
- `handleSetBlogSettings` — POST-only; decode `SetBlogSettingsRequest`; `req.Validate()`; call service; map `*domain.PermissionError`/`*domain.ErrUnauthorized` → 403; success `{"status":"success"}`. (Copy of `handleSetCustomFieldLabels`.)

### 3.4 Mock
Regenerate `internal/domain/mocks/mock_workspace_service.go` (`go generate ./internal/domain/...`).

## 4. Frontend changes

### 4.1 `console/src/services/api/workspace.ts`
Add `SetBlogSettingsRequest`/`Response` types and `setBlogSettings: (data) => api.post('/api/workspaces.setBlogSettings', data)` (next to `setCustomFieldLabels`). Reuse the existing `blog_settings` shape from `WorkspaceSettings`.

### 4.2 `console/src/components/settings/BlogSettings.tsx`
- Prop `isOwner` → `canManage`. Replace the three `isOwner` uses: read-only guard (`:194`), form-init effect guard (`:43`), themes-query `enabled` (`:38`).
- `handleSaveSettings`: replace `workspaceService.update(payload)` (`:146`) with
  `workspaceService.setBlogSettings({ workspace_id: workspace.id, blog_enabled: <intended>, blog_settings: values.blog_settings })`, keeping the `get` + `onWorkspaceUpdate` refresh and the default-theme side-effect (unchanged — separate `blogThemesApi` calls).
  - `<intended>` = `values.blog_enabled !== undefined ? values.blog_enabled === true : (workspace.settings.blog_enabled ?? false)` (preserves the "don't toggle when only editing settings" behavior, now sent explicitly since the endpoint always sets both).

### 4.3 `console/src/pages/WorkspaceSettingsPage.tsx`
Add `canManageBlog` state; derive in `fetchMembers` alongside `canManageCustomFields`:
`setCanManageBlog(currentUserMember?.role === 'owner' || currentUserMember?.permissions?.blog?.write === true)`.
Pass `canManage={canManageBlog}` to `<BlogSettings>` (replacing `isOwner`).

## 5. TDD test plan

**Domain** (`workspace_test.go`): `TestBlogSettings_Validate` (bounds + title); `TestSetBlogSettingsRequest_Validate` (workspace_id checks; valid; nil settings = disable; invalid page size; long title).

**Service** (`workspace_service_test.go`): `TestWorkspaceService_SetBlogSettings` — owner ✓; `blog:write` member ✓ (the fix); `blog:read`-only → `PermissionError`; nil/contacts-only perms → `PermissionError`; `FullPermissions` ✓; auth error; GetByID error; Update error; invalid settings rejected before Update; **preserves other settings** (only blog fields change); enable and disable toggles. Plus **add** an `UpdateWorkspace` sub-test "preserves blog settings" (existing blog config retained; request blog fields ignored) — there's no existing blog test to repurpose.

**HTTP** (`workspace_handler_test.go`): `TestWorkspaceHandler_HandleSetBlogSettings` — 405 / 400 (bad body) / 400 (validation) / 403 (permission) / 200 / 500.

**Integration** (`tests/integration/workspace_test.go`): `TestWorkspaceBlogSettingsSuite` (seeded users + DB-inserted `user_workspaces` perms, per the custom-fields suite) — owner ✓; **`blog:write` member ✓ (regression)**; `blog:read`-only → 403; no-blog-perm → 403; invalid settings → 400; **sole-writer guard** (member sets blog settings, owner `workspaces.update` general settings → blog config preserved); non-member → 4xx. Run only this function: `INTEGRATION_TESTS=true go test -run TestWorkspaceBlogSettingsSuite -v ./tests/integration/`.

**Frontend** (`BlogSettings.test.tsx`, new): `canManage=false` → read-only `Descriptions` (no form); `canManage=true` (blog enabled) → form renders; save calls `setBlogSettings` (not `update`). Mock `workspaceService` + `blogThemesApi`.

## 6. Commands
`make test-domain test-service test-http`; `go generate ./internal/domain/...`; `INTEGRATION_TESTS=true go test -run TestWorkspaceBlogSettingsSuite ./tests/integration/`; `cd console && npx vitest run src/components/settings/BlogSettings.test.tsx && npx tsc --noEmit && npx eslint <touched>`. Run `lingui:extract`/`compile` only if a new string is introduced.

## 7. Changelog
Add a bullet under the existing `## [32.3]`: blog settings (enable + title/SEO/pagination/feed) are now manageable by members with `blog:write` via a dedicated `POST /api/workspaces.setBlogSettings`; previously owner-only via `workspaces.update`, which no longer writes blog settings.

## 8. Out of scope
General presentation settings (logo/timezone/languages → `workspace:write`) and the sensitive Tier-2 fields (file manager, custom endpoint, provider IDs) — separate follow-ups.
