import * as AWS from 'aws-sdk'
import * as AWSXRay from 'aws-xray-sdk'
import { createLogger } from '../utils/logger'

const XAWS = AWSXRay.captureAWS(AWS)

const s3BucketName = process.env.ATTACHMENT_S3_BUCKET;
const urlExpiration = process.env.SIGNED_URL_EXPIRATION;

const logger = createLogger('attachmentUtils');

export class AttachmentUtils {
  constructor(
    private readonly s3 = new XAWS.S3({ signatureVersion: 'v4' }),
    private readonly bucketName = s3BucketName
  ) {}

  getSignedUrl(todoId: string): string {
    logger.info(`attachmentUtils - getSignedUrl!!!`);
    return this.s3.getSignedUrl('putObject', {
      Bucket: this.bucketName,
      Key: todoId,
      Expires: parseInt(urlExpiration ? urlExpiration : '300')
    });
  }

  generateS3AttachmentUrl(todoId: string) {
    logger.info(`attachmentUtils - generateS3AttachmentUrl!!!`);
    return `https://${this.bucketName}.s3.amazonaws.com/${todoId}`;
  }
}