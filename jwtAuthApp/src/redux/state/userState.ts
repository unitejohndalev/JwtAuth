import { PayloadAction, createSlice } from "@reduxjs/toolkit";




interface UserInfo {
  id: string;
  username: string;
  password: string;
  email: string;
  role: string;
}

interface UserState {
  users: UserInfo[];
  userInfo: UserInfo;
  isLoading: boolean;
  isLoadingDialog: boolean;
  isAddSuccess: boolean;
  saved: boolean;
  isAuthenticated: boolean;
  token: string;
}

const initialState: UserState = {
  users: [],
  userInfo: {
    id: '',
    username: '',
    password: '',
    email: '',
    role: ''
  },
  isLoading: false,
  isLoadingDialog: false,
  isAddSuccess: false,
  saved: false,
  isAuthenticated: localStorage.getItem('isAuthenticated') === 'true',
  token: localStorage.getItem('token') || ''
};

const userSlice = createSlice({
  name: 'users',
  initialState: {
    users: [],
    userInfo: {
      id: '',
      username: '',
      password: '',
      email: '',
      role: ''
    },
    isLoading: false,
    isLoadingDialog: false,
    isAddSuccess: false,
    saved: false,
    isAuthenticated: localStorage.getItem('isAuthenticated') === 'true',
    token: localStorage.getItem('token') || ''
  },
  reducers: {
    loginFetch: (state, action: PayloadAction<{ username: string; password: string }>) => {
      state.isLoading = true;
    },
    loginSuccess: (state, action) => {
      state.isLoading = false;
      state.isAuthenticated = true;
      state.token = action.payload.token;
      state.userInfo = action.payload.userInfo;
    },
    loginFailure: (state) => {
      state.isLoading = false;
      state.isAuthenticated = false;
      state.token = '';
    },
     logout: (state) => {
      state.isAuthenticated = false;
      state.token = '';
      state.userInfo = initialState.userInfo;
      console.log("Successfully log out and cleared user data"); //console if successfully log out and cleared local storage
    }
  }
});

export const { loginFetch, loginSuccess, loginFailure, logout } = userSlice.actions;

export const UserReducer = userSlice.reducer;

type UserInput = {
    username: string,
    password:string
}
//userInput slice
const inputInitialState: UserInput = {
  username: "",
  password: "",
};

const InputSlice = createSlice({
  name: "userInput",
  initialState: inputInitialState,
  reducers: {
    setUserField: (state, action: PayloadAction<Partial<UserInput>>) => {
      return { ...state, ...action.payload };
    },
  },
});

export const { setUserField } = InputSlice.actions;
export const InputReducer = InputSlice.reducer;
