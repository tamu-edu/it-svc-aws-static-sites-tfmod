#!/bin/bash

sam build \
  --use-container && \
sam local invoke CloudFrontCacheInvalidationFunction \
  --profile vpasc_vpmc_static_sites_multi_dev \
  --event ./event.json