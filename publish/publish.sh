#!/bin/bash
cd ../
tar --czvf vnet_v4.tar.gz vnet vnet.service
cd publish
 ./ossutil64 -c oss-cn-hongkong.aliyuncs.com cp ../vnet_v4.tar.gz oss://kitami-hk