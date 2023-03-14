import { Injectable } from '@nestjs/common';
import { ConfigService } from 'src/config/config.service';
import * as SendGrid from '@sendgrid/mail';
import { IMail } from 'src/mail/mail.interface';
@Injectable()
export class MailService {
  constructor(private readonly configService: ConfigService) {
    SendGrid.setApiKey(this.configService.get('sendgrid.key'));
  }

  async send(mail: IMail) {
    const transport = await SendGrid.send({
      ...mail,
      templateId: this.configService.get(mail.templateId),
    });
    // avoid this on production. use log instead :)
    console.log(`E-Mail sent to ${mail.to}`);
    return transport;
  }
}
