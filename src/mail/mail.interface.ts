import * as SendGrid from '@sendgrid/mail';

export interface IEmailVerificationData {
  urlVerifyEmail: string;
  browser: string;
  ipAddress: string;
  emailWasSentTo: string;
  urlContactUs: string;
  urlTermsOfUse: string;
}

export interface IForgotPasswordData {
  urlResetPassword: string;
  browser: string;
  ipAddress: string;
  emailWasSentTo: string;
  urlContactUs: string;
  urlTermsOfUse: string;
}

export interface IPasswordResetData {
  urlSupport: string;
  emailWasSentTo: string;
  urlContactUs: string;
  urlTermsOfUse: string;
}

type IBaseMail<T, D> = SendGrid.MailDataRequired & {
  templateId: T;
  dynamicTemplateData: D;
};
export type IMail =
  | IBaseMail<'sendgrid.confirmEmailTemplateId', IEmailVerificationData>
  | IBaseMail<'sendgrid.forgotPasswordEmailTemplateId', IForgotPasswordData>
  | IBaseMail<'sendgrid.resetPasswordEmailTemplateId', IPasswordResetData>;
