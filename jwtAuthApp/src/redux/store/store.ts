import createSagaMiddleware from "redux-saga";
import { configureStore } from "@reduxjs/toolkit";
import rootSaga from "../saga/rootSaga";
import { InputReducer, UserReducer } from "../state/userState";
import { DemoReducer } from "../state/demoState";



const saga = createSagaMiddleware();
export const store = configureStore({
  reducer: {

    InputReducer:InputReducer,
    DemoReducer:DemoReducer,
    UserReducer : UserReducer
  
    // add more reducers here
    

  },
  middleware: [saga],
});

saga.run(rootSaga);

export type RootState = ReturnType<typeof store.getState>;
export default store;
