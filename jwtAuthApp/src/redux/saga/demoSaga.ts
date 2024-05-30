// sagas/userListSaga.ts
import { call, put, takeEvery } from "redux-saga/effects";
import axios from "axios";
import { getDemoSuccess, getDemoFailure } from "../state/demoState";
import { getDemoConsole } from "../../api/Api";

// Fetch Demo Console

function* fetchDemo(): any {
  try {
    const token = localStorage.getItem("token");

    if (token) {
      const demo = yield call(() =>
        axios
          .get(getDemoConsole, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          })
          .then((res) => res.data)
      );
      yield put(getDemoSuccess(demo));
    } else {
      yield put(getDemoFailure("Token not found"));
    }
  } catch (error) {
    yield put(getDemoFailure(error.message));
  }
}

export function* DemoSaga() {
  yield takeEvery("demo/getDemoFetch", fetchDemo);
}
