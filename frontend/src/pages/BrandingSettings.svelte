<script lang="ts">
  import SettingsField from './SettingsField.svelte';
  import type { BrandingSettings } from '../lib/pages';

  let { branding }: { branding: BrandingSettings } = $props();
</script>

<section class="panel">
  <div class="section-heading"><h2>Custom branding</h2></div>
  <div class="form-grid">
    <SettingsField label="Site name" name="branding_site_name" id="branding-site-name" value={branding.SiteName} maxlength={80} placeholder="ObjectShare" hint="Used in navigation and page titles. Empty restores ObjectShare." />
    <SettingsField label="Tagline" name="branding_tagline" id="branding-tagline" value={branding.Tagline} maxlength={240} hint="Shown above the uploader and used as the page description." />
    <SettingsField label="Logo image URL" name="branding_logo_url" id="branding-logo" value={branding.LogoURL} maxlength={2048} placeholder="https://assets.example.com/logo.png" hint="Shown beside the site name. A transparent image works with both themes." />
    <SettingsField label="Header image URL" name="branding_header_image_url" id="branding-header" value={branding.HeaderImageURL} maxlength={2048} placeholder="https://assets.example.com/banner.webp" hint="An optional banner above the upload page." />
    <SettingsField label="Site icon URL" name="branding_favicon_url" id="branding-favicon" value={branding.FaviconURL} maxlength={2048} placeholder="https://assets.example.com/favicon.png" hint="Browser tab icon (favicon). Use a square image or ICO file." />
    <div class="field">
      <label class="form-label" for="branding-footer">Footer message</label>
      <textarea class="form-control" id="branding-footer" name="branding_footer_message" rows="3" maxlength="2000" value={branding.FooterMessage}></textarea>
      <div class="form-hint">Plain text, including multiple lines. Shown alongside the existing ObjectShare version and author credit.</div>
    </div>
    <SettingsField label="Footer link text" name="branding_footer_link_text" id="branding-footer-link-text" value={branding.FooterLinkText} maxlength={80} placeholder="Privacy policy" />
    <SettingsField label="Footer link URL" name="branding_footer_link_url" id="branding-footer-link-url" value={branding.FooterLinkURL} maxlength={2048} placeholder="https://example.com/privacy" hint="Set both link fields, or leave both empty." />
  </div>
  <p class="form-hint mt-3">Images need stable public HTTPS URLs or root-relative paths served by your reverse proxy. Empty optional fields remove the customization. Saving activates branding on this replica immediately.</p>
</section>
