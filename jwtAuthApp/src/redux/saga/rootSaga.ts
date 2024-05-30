// rootSaga.ts
import { all } from "redux-saga/effects";
import { DemoSaga } from "./demoSaga";
import { AuthSaga } from "./authSaga";



export default function* rootSaga() {
  yield all([
    DemoSaga(),
    AuthSaga()
    //add saga here
  ]);
}
