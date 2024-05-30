import { createSlice } from "@reduxjs/toolkit";



const demoSlice = createSlice({
  name: "demo",
  initialState: {
    demoConsole: null,
    isLoading: false,
    isAddSuccess: false,
    error: null,
  },
  reducers: {
    getDemoFetch: (state) => {
      state.isLoading = true;
      state.error = null; 
    },
    getDemoSuccess: (state, action) => {
      state.demoConsole = action.payload;
      state.isLoading = false;
    },
    getDemoFailure: (state, action) => {
      state.isLoading = false;
      state.error = action.payload;
    },
  },
});

export const { getDemoFetch, getDemoSuccess, getDemoFailure } = demoSlice.actions;

export const DemoReducer = demoSlice.reducer;

