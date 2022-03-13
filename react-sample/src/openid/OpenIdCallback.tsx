import React, { useEffect } from 'react';
import { completeAuthorization } from './openid-manager';
import { authCallbackPath } from './openid-settings';

export const OpenIdCallback: React.FC = (props) => {
  const url = window.location.href;
  const isOpenIdCallback = url.includes(authCallbackPath);
  useEffect(() => {
    if (isOpenIdCallback) {
      // noinspection JSIgnoredPromiseFromCall
      completeAuthorization();
    }
  }, [isOpenIdCallback]);

  if (isOpenIdCallback) return null;

  return <>{props.children}</>;
};
