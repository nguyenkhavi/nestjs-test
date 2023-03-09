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

export interface IPasswordReset {
  urlSupport: string;
  emailWasSentTo: string;
  urlContactUs: string;
  urlTermsOfUse: string;
}
