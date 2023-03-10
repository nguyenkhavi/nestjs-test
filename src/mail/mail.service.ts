import { Injectable } from '@nestjs/common';
import { ConfigService } from 'src/config/config.service';
import * as SendGrid from '@sendgrid/mail';
import {
  IEmailVerificationData,
  IForgotPasswordData,
  IPasswordReset,
} from 'src/mail/mail.interface';
@Injectable()
export class MailService {
  constructor(private readonly configService: ConfigService) {
    SendGrid.setApiKey(this.configService.get('sendgrid.key'));
  }
  async sendConfirmEmail(
    mail: Omit<SendGrid.MailDataRequired, 'dynamicTemplateData'>,
    dynamicTemplateData: IEmailVerificationData,
  ) {
    const transport = await SendGrid.send({
      templateId: this.configService.get('sendgrid.confirmEmailTemplateId'),
      dynamicTemplateData,
      ...mail,
    });
    // avoid this on production. use log instead :)
    console.log(`E-Mail sent to ${mail.to}`);
    return transport;
  }
  async sendForgotPasswordEmail(
    mail: Omit<SendGrid.MailDataRequired, 'dynamicTemplateData'>,
    dynamicTemplateData: IForgotPasswordData,
  ) {
    const transport = await SendGrid.send({
      templateId: this.configService.get(
        'sendgrid.forgotPasswordEmailTemplateId',
      ),
      dynamicTemplateData,
      ...mail,
    });
    // avoid this on production. use log instead :)
    console.log(`E-Mail sent to ${mail.to}`);
    return transport;
  }

  async sendPasswordResetEmail(
    mail: Omit<SendGrid.MailDataRequired, 'dynamicTemplateData'>,
    dynamicTemplateData: IPasswordReset,
  ) {
    const transport = await SendGrid.send({
      templateId: this.configService.get(
        'sendgrid.resetPasswordEmailTemplateId',
      ),
      dynamicTemplateData,
      ...mail,
    });
    // avoid this on production. use log instead :)
    console.log(`E-Mail sent to ${mail.to}`);
    return transport;
  }
}
