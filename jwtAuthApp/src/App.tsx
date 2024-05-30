import { Navigate, Route, Routes } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import MainPage from "./pages/MainPage";
import { useSelector } from "react-redux";
import { RootState } from "./redux/store/store";

function App() {
  const isAuthenticated = useSelector((state: RootState) => state.UserReducer.isAuthenticated);

 
  return (
    <>
      <Routes>
        {isAuthenticated ? (
          <>
            <Route path="/" element={<Navigate to="/home" />} />
            <Route path="/home/*" element={<MainPage />} />
          </>
        ) : (
          <>
            <Route index element={<LandingPage />} />
            <Route path="/" element={<LandingPage />} />
            <Route path="*" element={<Navigate to="/" />} />
          </>
        )}
      </Routes>
    </>
  );
}

export default App;
