// authSaga.js
import { call, put, takeLatest } from 'redux-saga/effects';
import axios from 'axios';

import { loginSuccess, loginFailure, loginFetch } from '../state/userState'

import { postPerson } from '../../api/Api';

function* handleLogin(action : any) {
  try {
    const { username, password } = action.payload;
    const response = yield call(axios.post, postPerson, { username, password });
    const { data } = response;

    // Save token to localStorage
    localStorage.setItem('token', data.token);
    localStorage.setItem('isAuthenticated', 'true');

    //console the token
       console.log("Successfully logged in:", data.token);
    yield put(loginSuccess(data));
  } catch (error) {
    yield put(loginFailure());
  }
}

export function* AuthSaga() {
  yield takeLatest(loginFetch.type, handleLogin);
}


