#!/bin/bash
# Weekly S3 backup: sync all Spaces content to a local backup directory
# This provides a second copy in case of DO Spaces outage
BACKUP_DIR=/home/recruiting/backups/s3-mirror
mkdir -p $BACKUP_DIR
cd /home/recruiting/bearcats
source .env
export AWS_ACCESS_KEY_ID=$SPACES_KEY
export AWS_SECRET_ACCESS_KEY=$SPACES_SECRET
aws s3 sync s3://cap-recruiting-videos/ $BACKUP_DIR/ --endpoint-url https://nyc3.digitaloceanspaces.com 2>&1 | tail -5 >> /var/log/cap_s3_backup.log
echo "$(date): S3 backup completed" >> /var/log/cap_s3_backup.log
