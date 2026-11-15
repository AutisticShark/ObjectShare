export interface Branding {
  SiteName: string;
  Tagline: string;
  LogoURL: string;
  HeaderImageURL: string;
  FaviconURL: string;
  FooterMessage: string;
  FooterLinkText: string;
  FooterLinkURL: string;
}

export interface Bootstrap {
  Page: string;
  Data: Record<string, unknown>;
  Branding: Branding;
}

export function readBootstrap(root: ParentNode): Bootstrap | null {
  const element = root.querySelector('#objectshare-page');
  if (!element?.textContent) return null;
  const value: unknown = JSON.parse(element.textContent);
  if (!value || typeof value !== 'object') throw new Error('Invalid page data.');
  const boot = value as Bootstrap;
  if (typeof boot.Page !== 'string' || !boot.Data || typeof boot.Data !== 'object' || !boot.Branding || typeof boot.Branding.SiteName !== 'string') throw new Error('Invalid page data.');
  return boot;
}
