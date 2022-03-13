async function getData(url: string) {
  try {
    const data = await fetch(url,
      {
        headers: {
          'Authorization': `Bearer ${getAccessToken()}`,
          'Content-Type': 'application/json;'
        }
      })
    if (!data.ok) {
      alert('Error (Unauthorized)');
      return null;
    }
    const dt = await data.json();
    if (dt != null) {
      console.log(dt);
      alert(dt);
    }
  } catch (e) {
    alert(e);
  }
}

export async function getValues() {
  return await getData('/api/values');
}

export async function getUsers() {
  return await getData('/api/permissions/users');
}

export async function getDocuments() {
  return await getData('/api/permissions/documents');
}

let _accessToken = '';
export function setAccessToken(token: string) {
  _accessToken=token;
}
function getAccessToken() {
  return _accessToken;
}
