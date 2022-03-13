import { UserManager, UserManagerSettings } from 'oidc-client-ts';
import {
  authCallbackPath,
  backendUri,
  clientId,
  redirectUri,
  scopes,
} from './openid-settings';

function getClientSettings(): UserManagerSettings {
  return {
    authority: backendUri,
    client_id: clientId,
    redirect_uri: redirectUri,
    post_logout_redirect_uri: backendUri,
    response_type: 'code',
    filterProtocolClaims: true,
    loadUserInfo: false,
    scope: scopes,
    extraTokenParams: { scope: scopes },
  };
}
let manager: UserManager | undefined;
function getManager() {
  if (!manager) {
    manager = new UserManager(getClientSettings());
  }
  return manager;
}

export async function openExternalLoginPopup(provider: string) {
  try {
    const user = await getManager().signinPopup({
      extraQueryParams: { provider: provider },
    } as any);
    return user;
  } catch (e) {
    console.error('Error during external authentication', e);
    throw e;
  }
}

export async function completeAuthorization() {
  const user = new UserManager({
    redirect_uri: redirectUri,
    client_id: clientId,
    authority: backendUri,
  }).signinPopupCallback();
  return user;
}
