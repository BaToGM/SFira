import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";

import { fetchDashboardData, type DashboardData } from "../app/api";

type SwinraState = {
  status: "idle" | "loading" | "ready" | "error";
  data: DashboardData | null;
  filters: {
    minScore: number;
    userType: "all" | "couple" | "single";
    fetish: string;
  };
};

const initialState: SwinraState = {
  status: "idle",
  data: null,
  filters: {
    minScore: 3.5,
    userType: "all",
    fetish: "",
  },
};

export const loadDashboard = createAsyncThunk("swinra/loadDashboard", fetchDashboardData);

const swinraSlice = createSlice({
  name: "swinra",
  initialState,
  reducers: {
    setMinScore(state, action: { payload: number }) {
      state.filters.minScore = action.payload;
    },
    setUserType(state, action: { payload: SwinraState["filters"]["userType"] }) {
      state.filters.userType = action.payload;
    },
    setFetish(state, action: { payload: string }) {
      state.filters.fetish = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loadDashboard.pending, (state) => {
        state.status = "loading";
      })
      .addCase(loadDashboard.fulfilled, (state, action) => {
        state.status = "ready";
        state.data = action.payload;
      })
      .addCase(loadDashboard.rejected, (state) => {
        state.status = "error";
      });
  },
});

export const { setFetish, setMinScore, setUserType } = swinraSlice.actions;
export default swinraSlice.reducer;
