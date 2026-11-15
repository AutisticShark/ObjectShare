// Page data contracts. Field names are the Go field names the templates used,
// times are ISO 8601 strings, and secrets never reach the browser.

export type ISOTime = string;
/** A Go time.Duration rendered with its String form, for example "15m0s". */
export type Duration = string;

export interface CaptchaWidget {
  SiteKey: string;
  Action: string;
}

/** The exposed subset of db.User. */
export interface PageUser {
  ID: string;
  Email: string;
  DisplayName: string;
  Role: string;
  Active: boolean;
  DarkMode: boolean;
  IsPaid: boolean;
  UploadQuotaBytes: number;
  CreditBalance: number;
  EmailVerifiedAt: ISOTime | null;
  CreatedAt: ISOTime;
  LastLoginAt: ISOTime | null;
  MFA: { Method: string };
}

/** Fields common to every page. */
export interface BasePage {
  Version: string;
  CSRF: string;
  User?: PageUser | null;
  Error?: string;
  Message?: string;
  /** Used only where the old templates printed the site name in the body. */
  Branding?: { SiteName: string } | null;
}

export interface BillingGatewayOption {
  Key: string;
  Label: string;
}

export interface OAuthButton {
  Key: string;
  Label: string;
  URL: string;
}

export interface OAuthAccountProvider {
  Key: string;
  Label: string;
  Configured: boolean;
  Linked: boolean;
}

/* ---------- Authentication ---------- */

export type AuthPageName = 'login' | 'signup' | 'setup';

/** login.html, signup.html and setup.html. */
export interface AuthPageData extends BasePage {
  Email?: string;
  DisplayName?: string;
  Next?: string;
  SignupEnabled?: boolean;
  Setup?: boolean;
  SetupTokenRequired?: boolean;
  OAuthProviders?: OAuthButton[] | null;
  Captcha?: CaptchaWidget | null;
}

/** mfa.html. The two extra fields replace the template's reads of the password hash and recovery hashes. */
export interface MFAPageData extends BasePage {
  Action?: string;
  Method?: string;
  Secret?: string;
  Codes?: string[] | null;
  EmailAvailable?: boolean;
  /** Whether the signed-in account has a password (the template read User.PasswordHash). */
  HasPassword?: boolean;
  /** Number of unused recovery codes (the template used len User.MFA.Recovery). */
  RecoveryCount?: number;
}

/* ---------- Account and billing ---------- */

export interface CreditTransactionRow {
  Delta: string;
  Balance: string;
  Description: string;
  CreatedAt: string;
  Positive: boolean;
}

/** Fields the billing-summary partial needs; shared by the account and billing pages. */
export interface BillingSummaryData {
  CSRF: string;
  PlanName?: string;
  PlanRenews?: string;
  PlanStatus?: string;
  PlanActive?: boolean;
  PlanCanceling?: boolean;
  BillingEnabled?: boolean;
  BillingAccount?: boolean;
  CreditPlan?: boolean;
  CreditBalance?: string;
  CreditCurrency?: string;
  MinTopUpCredits?: number;
  MaxTopUpCredits?: number;
  TopUpGateways?: BillingGatewayOption[] | null;
  CreditTransactions?: CreditTransactionRow[] | null;
}

export interface AccountFile {
  ID: string;
  Name: string;
  /** Already formatted, for example "1.5 MiB". */
  Size: string;
  /** Already formatted, for example "2026-11-15 10:30 UTC". */
  CreatedAt: string;
}

/** account.html. */
export interface AccountPageData extends BasePage, BillingSummaryData {
  User: PageUser;
  QuotaLabel?: string;
  HasPassword: boolean;
  VerificationEnabled?: boolean;
  VerificationPurchases?: boolean;
  VerificationUploads?: boolean;
  Files?: AccountFile[] | null;
  OAuthProviders?: OAuthAccountProvider[] | null;
}

/** billing.html. */
export interface BillingPageData extends BasePage, BillingSummaryData {
  User: PageUser;
  QuotaLabel?: string;
}

export interface PlanCard {
  ID: string;
  Name: string;
  Description: string;
  Price: string;
  CurrencyPrice?: string;
  Storage: string;
  Retention: string;
  Duration: string;
  DirectLinks: boolean;
  RequestID: string;
}

/** plans.html. User is null for visitors. */
export interface PlansPageData extends BasePage {
  Plans?: PlanCard[] | null;
  BillingEnabled?: boolean;
  VerificationRequired?: boolean;
  CreditBalance?: string;
}

/** The public fields of db.Invoice. */
export interface PageInvoice {
  ID: string;
  Kind: string;
  Name: string;
  Description: string;
  Email: string;
  Credits: number;
  AmountMinor: number;
  Currency: string;
  DurationDays: number;
  Status: string;
  Gateway: string;
  PaymentID: string;
  PaidAt: ISOTime | null;
  CreatedAt: ISOTime;
  ExpiresAt: ISOTime;
  EmailSentAt: ISOTime | null;
}

/** invoices.html. Page is zero-based. */
export interface InvoicesPageData extends BasePage {
  User: PageUser;
  Invoices?: PageInvoice[] | null;
  Page: number;
  NextPage: number;
  PreviousPage: number;
  HasNext: boolean;
}

/** admin_invoices.html. Page is one-based and the URLs are ready to use. */
export interface AdminInvoicesPageData extends BasePage {
  User: PageUser;
  Invoices?: PageInvoice[] | null;
  Search: string;
  Filter: string;
  Page: number;
  PreviousURL?: string;
  NextURL?: string;
}

/** invoice.html. */
export interface InvoicePageData extends BasePage {
  User: PageUser;
  Invoice: PageInvoice;
  Gateways?: BillingGatewayOption[] | null;
  CanPay: boolean;
  VerificationRequired?: boolean;
  CheckoutExpired?: boolean;
  ReceiptEnabled?: boolean;
}

/* ---------- Files and sharing ---------- */

export interface WorkspaceFile extends AccountFile {
  Access: string;
  Encrypted: boolean;
}

/** files.html. Page is one-based. */
export interface FilesPageData extends BasePage {
  User: PageUser;
  Files?: WorkspaceFile[] | null;
  Search: string;
  Filter: string;
  QuotaLabel?: string;
  Page: number;
  PreviousURL?: string;
  NextURL?: string;
}

/** file_view.html. */
export interface FileViewPageData extends BasePage {
  FileID: string;
  FileName: string;
  /** Already formatted. */
  FileSize: string;
  FileSHA256: string;
  FileSHA3: string;
  CreatedAt: ISOTime;
  UpdatedAt: ISOTime;
  DirectURL: string;
  /** Client-encryption metadata; empty when the file is not client-encrypted. */
  ClientEncryption: string;
  CanManage: boolean;
  Encrypted: boolean;
  ChecksumsVerified: boolean;
  CanDirectLink: boolean;
  PlanDirectLinks: boolean;
  SignupEnabled?: boolean;
  Captcha?: CaptchaWidget | null;
  DownloadToken: string;
}

/** sharing.html. */
export interface SharingPageData extends BasePage {
  FileID: string;
  FileName: string;
  ShareURL: string;
  Mode: string;
  SavedMode: string;
  Recipients: string;
  ClientEncrypted: boolean;
  ClientEncryption: string;
  SignupEnabled?: boolean;
}

export interface UploadedFileResult {
  ID: string;
  Name: string;
}

/** upload_results.html. */
export interface UploadResultsPageData extends BasePage {
  Files?: UploadedFileResult[] | null;
}

/* ---------- Administration ---------- */

export interface AdminStats {
  Users: number;
  BannedUsers: number;
  ShadowbannedUsers: number;
  DisabledUsers: number;
  Files: number;
  StorageBytes: number;
  PendingUploads: number;
  ActivePlans: number;
  PaidInvoices: number;
  PendingInvoices: number;
  UnsentReceipts: number;
}

export interface SetupCheck {
  Name: string;
  Detail: string;
  URL: string;
  Configured: boolean;
}

/** admin_dashboard.html. */
export interface AdminOverviewPageData extends BasePage {
  User: PageUser;
  Stats: AdminStats;
  /** Already formatted stored size. */
  Storage: string;
  StorageService: string;
  Checks?: SetupCheck[] | null;
}

export interface AdminUserRow {
  ID: string;
  Email: string;
  DisplayName: string;
  Role: string;
  ModerationStatus: string;
  EmailVerified: boolean;
  Active: boolean;
  IsCurrent: boolean;
  IsPaid: boolean;
  UploadQuotaMiB: number;
  CreatedAt: string;
  LastLogin: string;
  StorageUsed: string;
  CreditBalance: string;
  CreditRequestID: string;
}

/** admin_users.html. */
export interface AdminUsersPageData extends BasePage {
  User: PageUser;
  Users?: AdminUserRow[] | null;
  Search: string;
  Filter: string;
  /** Query string (with its leading "?" or empty) appended to every action. */
  QuerySuffix: string;
  /** One-based, like the other workspace directories. */
  Page: number;
  PreviousURL?: string;
  NextURL?: string;
  TotalUsers: number;
  TotalStorageUsed: string;
  /** Whether the signed-in administrator has a password (the template read User.PasswordHash). */
  HasPassword: boolean;
}

export interface AdminPlanRow {
  ID: string;
  Name: string;
  Description: string;
  /** Formatted, for example "1.50". */
  StorageQuotaGiB: string;
  RetentionDays: number;
  DirectLinks: boolean;
  Price: number;
  DurationDays: number;
  Active: boolean;
  SortOrder: number;
}

/** admin_plans.html. */
export interface AdminPlansPageData extends BasePage {
  User: PageUser;
  Plans?: AdminPlanRow[] | null;
}

/* ---------- Administration: configuration ---------- */

export interface BrandingSettings {
  SiteName: string;
  Tagline: string;
  LogoURL: string;
  HeaderImageURL: string;
  FaviconURL: string;
  FooterMessage: string;
  FooterLinkText: string;
  FooterLinkURL: string;
}

export interface EmailSettings {
  Provider: string;
  FromAddress: string;
  FromName: string;
  ReplyTo: string;
  Timeout: Duration;
  SMTP: { Host: string; Port: number; TLSMode: string; Username: string };
  Alibaba: { Region: string };
  SES: { Region: string; ConfigurationSet: string };
}

export interface OAuthProviderSettings {
  Enabled: boolean;
  ClientID: string;
}

/** The fields shared by every S3-compatible backend (S3, B2, OSS, COS, OCI, GCS and, with extras, R2). */
export interface StorageBackendSettings {
  BucketName: string;
  Endpoint: string;
  Region: string;
  PresignLinkTimeout: Duration;
  PresignUploadTimeout: Duration;
}

export interface R2Settings extends StorageBackendSettings {
  AccountID: string;
}

export interface S3Settings extends StorageBackendSettings {
  UsePathStyle: boolean;
}

/** config.RuntimeConfig with secrets redacted. */
export interface RuntimeSettings {
  Branding: BrandingSettings;
  MaxFileSize: number;
  SecureCookies: boolean;
  Upload: { GuestEnabled: boolean; MaxFilesPerBatch: number; MaxPendingGuestMiB: number };
  Retention: { GuestDays: number; UnpaidDays: number };
  Billing: {
    PublicURL: string;
    CreditCurrency: string;
    MinTopUpCredits: number;
    MaxTopUpCredits: number;
    Stripe: { Enabled: boolean };
    PayPal: { Enabled: boolean; Environment: string; ClientID: string; WebhookID: string };
  };
  Email: EmailSettings;
  Auth: {
    SignupEnabled: boolean;
    EmailVerification: { PublicURL: string; RequireForPurchases: boolean; RequireForUploads: boolean };
    OAuth: { PublicURL: string; Google: OAuthProviderSettings; GitHub: OAuthProviderSettings; Discord: OAuthProviderSettings };
  };
  Captcha: {
    Provider: string;
    SiteKey: string;
    ExpectedHostname: string;
    ProtectLogin: boolean;
    ProtectSignup: boolean;
    ProtectUpload: boolean;
    ProtectDownload: boolean;
  };
  RateLimit: {
    Enabled: boolean;
    Window: Duration;
    APILimit: number;
    LoginLimit: number;
    SignupLimit: number;
    UploadLimit: number;
    DownloadLimit: number;
  };
  StorageService: string;
  StoragePath: string;
  Encryption: { Enabled: boolean; Method: string };
  R2: R2Settings;
  S3: S3Settings;
  B2: StorageBackendSettings;
  OSS: StorageBackendSettings;
  COS: StorageBackendSettings;
  OCI: StorageBackendSettings;
  GCS: StorageBackendSettings;
}

/** Which secrets are stored; the values themselves are never sent. */
export interface SettingsSecretState {
  SMTPPassword: boolean;
  AlibabaMailAccess: boolean;
  AlibabaMailSecret: boolean;
  SESAccess: boolean;
  SESSecret: boolean;
  SESSession: boolean;
  Captcha: boolean;
  Google: boolean;
  GitHub: boolean;
  Discord: boolean;
  Encryption: boolean;
  StripeSecret: boolean;
  StripeWebhook: boolean;
  PayPalSecret: boolean;
  R2Access: boolean;
  R2Secret: boolean;
  S3Access: boolean;
  S3Secret: boolean;
  S3Session: boolean;
  B2Access: boolean;
  B2Secret: boolean;
  OSSAccess: boolean;
  OSSSecret: boolean;
  COSAccess: boolean;
  COSSecret: boolean;
  OCIAccess: boolean;
  OCISecret: boolean;
  GCSAccess: boolean;
  GCSSecret: boolean;
}

/** admin_settings.html. */
export interface AdminSettingsPageData extends BasePage {
  User: PageUser;
  Revision: string;
  UpdatedAt: string;
  UpdatedBy: string;
  TrustedProxyCIDRs: string;
  Config: RuntimeSettings;
  Secrets: SettingsSecretState;
  ActivationPending: boolean;
  EmailEnabled: boolean;
}

/* ---------- Standalone messages ---------- */

export type MessagePageName = 'verify_email' | 'oauth_error' | 'oauth_continue' | 'billing_problem';

/** verify_email.html. */
export interface VerifyEmailPageData extends BasePage {
  Success?: boolean;
  Token?: string;
  UserID?: string;
}

/** oauth_error.html. */
export interface OAuthErrorPageData extends BasePage {
  Back: string;
  BackLabel: string;
}

/** oauth_continue.html. */
export interface OAuthContinuePageData extends BasePage {
  Location: string;
}

/** billing_problem.html. Message holds the problem text; InvoiceURL is empty when no invoice applies. */
export interface BillingProblemPageData extends BasePage {
  InvoiceURL?: string;
}

export type MessagePageData = VerifyEmailPageData | OAuthErrorPageData | OAuthContinuePageData | BillingProblemPageData;

/** Every page this module describes. */
export type PageData =
  | AuthPageData
  | MFAPageData
  | AccountPageData
  | BillingPageData
  | PlansPageData
  | InvoicesPageData
  | AdminInvoicesPageData
  | InvoicePageData
  | FilesPageData
  | FileViewPageData
  | SharingPageData
  | UploadResultsPageData
  | AdminOverviewPageData
  | AdminUsersPageData
  | AdminPlansPageData
  | AdminSettingsPageData
  | MessagePageData;

/** "USD 12.00", the form the invoice templates printed. */
export function invoiceTotal(invoice: Pick<PageInvoice, 'Currency' | 'AmountMinor'>): string {
  return `${invoice.Currency} ${(invoice.AmountMinor / 100).toFixed(2)}`;
}
