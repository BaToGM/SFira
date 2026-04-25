import { configureStore } from "@reduxjs/toolkit";

import swinraReducer from "../features/swinraSlice";

export const store = configureStore({
  reducer: {
    swinra: swinraReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
