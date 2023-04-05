import { Injectable } from '@nestjs/common';
import * as KMS from 'aws-sdk/clients/kms';
import { ConfigService } from 'src/config/config.service';
@Injectable()
export class KmsService {
  constructor(private configService: ConfigService) {
    this.kms = new KMS({
      accessKeyId: this.configService.get('aws.accessKeyId'),
      secretAccessKey: this.configService.get('aws.secretAccessKeyId'),
      region: this.configService.get('aws.region'),
    });
  }
  private kms: KMS;

  async encrypt(source: string) {
    const params = {
      KeyId: this.configService.get('aws.kmsKeyId'),
      Plaintext: source,
    };
    const { CiphertextBlob } = await this.kms.encrypt(params).promise();

    // store encrypted data as base64 encoded string
    return CiphertextBlob.toString('base64');
  }

  async decrypt(source: string) {
    const params = {
      CiphertextBlob: Buffer.from(source, 'base64'),
    };
    const { Plaintext } = await this.kms.decrypt(params).promise();
    return Plaintext.toString();
  }
}
