import React from 'react';
import logo from './logo.svg';
import './App.css';
import {getDocuments, getUsers, getValues, setAccessToken} from "./api/fetcher";
import {openExternalLoginPopup} from "./openid/openid-manager";

async function signInVia(provider: string) {
  try {
    const user = await openExternalLoginPopup(provider);
    alert('Authentication succeeded');
    console.log('User', user);
    setAccessToken(user.access_token);
  } catch (e) {
    console.error('Error during authentication', e);
  }

}

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo"/>
        <h1>Sign-in via OAuth</h1>
        <div>
          <button onClick={() => signInVia('Google')}>Google</button>
          <button onClick={() => signInVia('Facebook')}>Facebook</button>
          <button onClick={() => signInVia('Microsoft')}>Microsoft</button>
          <button onClick={() => signInVia('OpenIdConnect')}>AzureAD</button>
          <button onClick={() => signInVia('GitHub')}>GitHub</button>
          <button onClick={() => signInVia('Twitter')}>Twitter</button>
        </div>
        <h1>Values</h1>
        <div>
          <button onClick={getValues}>Get Values</button>
          <button onClick={getDocuments}>Get Documents</button>
          <button onClick={getUsers}>Get Users</button>
        </div>
      </header>
    </div>
  );
}

export default App;
